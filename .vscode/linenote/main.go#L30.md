regexp.MustCompile
- function from the regexp package that compiles a regular expression into a *regexp.Regexp object
- takes a string as an argument and compiles it into a regular expression. 
- **checks and makes sure that the regular expression is absolutely complete

`(?i)\b` + regexp.QuoteMeta(word) + "\b"
- regular expression pattern that is being compiled by MustCompile
- (?i) - case-insensitive flag for a regular expression. 

- \b - word boundary - match the word exactly and not a larger part of the word. kerfuffle, not kerfuffle!

- \ is an escape character u string literals. 

- \b ensure that the regex matches whole words only. 

- regexp.QuoteMeta(word) - this function takes the variable word (string kerfuffle) and escapes any special regex characters. 
- Regular expressions have special meanings for characters like ., *, +, etc. For example, if your word were "a.b", the period (.) in the word would normally mean "any character" in regex.

- QuoteMeta ensure that the word is treated as a literal string in regex. 
- i.e. If word is "kerfuffle", QuoteMeta will simply return "kerfuffle", but if word was "a.b", it would return "a\.b" to make sure that the period . is treated as just a period, not as a "match any character" operator in regex.

- \b (at end) - is a word boundary marker. it ensures that the match happens at the end of the word and doesn't match part of a larger word. 

Summary - "(?i)\b" + regexp.QuoteMeta(word) + "\b"
- is word is "kerfuffle", it becomes "(?i)\\kerfuffle\\b"
- this will match the word case insensitively, ensure that the match only happens to a complete word, and \b at the end ensure it matches it exactly. 

- MustCompile is used on that pattern to turn it into a regular expression and stores it in re. Now we can use the variable re to find and replace occurences of this word. 


