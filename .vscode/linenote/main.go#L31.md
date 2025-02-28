body = re.ReplaceAllString(body, "****") matches the word 

body - holds the text recieved by the method that we want to clean up. 

re - regular expression object created right before. contains the compiled regex pattern that we want to use to find the word. 

ReplaceAllString(body, "****")
- method of the regular expression object re. 
It will look for all occurences in the body string that match the regex pattern stored in re and will replace them with the provided string "***"