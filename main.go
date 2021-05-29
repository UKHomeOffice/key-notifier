package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/iam"
	"github.com/aws/aws-sdk-go/service/ses"
)

func getIAMSession() *iam.IAM {
	sess, err := session.NewSession()
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return nil
	}
	return iam.New(sess)
}

func getSESSession() *ses.SES {
	sess, err := session.NewSession()
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return nil
	}
	return ses.New(sess, aws.NewConfig().WithRegion("eu-west-1"))
}

func getTags(svc *iam.IAM, m *iam.AccessKeyMetadata) *string {

	input := &iam.ListUserTagsInput{
		MaxItems: aws.Int64(1000),
		UserName: aws.String(*m.UserName),
	}

	result, err := svc.ListUserTags(input)
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return nil
	}

	for _, tag := range result.Tags {
		if *tag.Key == "key_rotation" {
			if *tag.Value != "false" {
				continue
			}
			log.Println("user ignored: " + *m.UserName)
			return nil
		}
	}

	for _, tag := range result.Tags {
		if *tag.Key != "email" {
			continue
		}
		return tag.Value
	}
	log.Println("no email found for user with expired key: ", *m.UserName)
	return nil
}

func staleKey(svc *iam.IAM, u *iam.User) (*iam.AccessKeyMetadata, *int) {

	prd, ok := os.LookupEnv("PERIOD")
	if !ok {
		log.Printf("no expiry period specified - defaulting to 90 days\n")
		prd = "90"
	}

	period, err := strconv.Atoi(prd)
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return nil, nil
	}

	input := &iam.ListAccessKeysInput{
		UserName: aws.String(*u.UserName),
	}

	result, err := svc.ListAccessKeys(input)
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return nil, nil
	}

	for _, key := range result.AccessKeyMetadata {
		if key.CreateDate.Before(time.Now().AddDate(0, 0, -period)) {
			return key, &period
		}
	}
	return nil, nil
}

func notify(k *iam.AccessKeyMetadata, email string, period *int) {

	svc := getSESSession()

	sender, ok := os.LookupEnv("SENDER")
	if !ok {
		log.Printf("no sender email address specified - defaulting to no-reply@digital.homeoffice.gov.uk\n")
		sender = "no-reply@digital.homeoffice.gov.uk"
	}

	input := &ses.SendEmailInput{
		Destination: &ses.Destination{
			ToAddresses: []*string{
				aws.String(email),
			},
		},
		Message: &ses.Message{
			Body: &ses.Body{
				Text: &ses.Content{
					Charset: aws.String("UTF-8"),
					Data: aws.String("Hi,\nAWS access key " + *k.AccessKeyId + " belonging to user " + *k.UserName +
						" was created over " + fmt.Sprint(*period) + " days ago.\nYou should consider rotating it. " +
						"Please raise a ticket on the ACP Service Desk so that we can either rotate or add it to our ignore list.\n" +
						"Thanks,\nACP Support Team"),
				},
			},
			Subject: &ses.Content{
				Charset: aws.String("UTF-8"),
				Data:    aws.String("Reminder: you have old AWS keys"),
			},
		},
		Source: aws.String(sender),
	}

	_, err := svc.SendEmail(input)
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return
	}
}

func handle() {
	svc := getIAMSession()

	usersInput := &iam.ListUsersInput{MaxItems: aws.Int64(1000)}
	result, err := svc.ListUsers(usersInput)
	if err != nil {
		log.Printf("error: %s\n", err.Error())
		return
	}

	for _, user := range result.Users {
		if k, n := staleKey(svc, user); k != nil {
			if email := getTags(svc, k); email != nil {
				notify(k, *email, n)
				log.Println("notified " + *k.UserName + " at " + *email + " re: stale access key " + *k.AccessKeyId + " created on: " + k.CreateDate.String())
			}
		}
	}
}

func main() {
	lambda.Start(handle)
}
