## key notifier
A simple Lambda function that checks access keys in an AWS account and sends notifications to users with an email address in their tags.  

Tag an IAM user with `key_rotation: false` to ignore their keys.  
Use tags starting with `email` to specify recipient addresses.  

The Lambda function itself accepts the following environmental variables:  
`PERIOD` - number days since creation before we consider a key too old  
`SENDER` - sender address for notification emails  

For deployment resources, see acp-lambda-keynotifier in Gitlab.