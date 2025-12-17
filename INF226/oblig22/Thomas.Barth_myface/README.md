# MyFace Report for *NAME*
## Tasks
### a) SQL Injection

> How did you do the SQL injection and what did you do to fix it?
I injected the SQL by submitting a username that closed the expected quoted value and appended an INSERT statement, which caused the database to execute both the original and my injected SQL. Because the app concatenated raw user input into query strings, characters like '; changed the SQL grammar and allowed creation of accounts. 
I fixed this by converting all statements to parameterized queries (using ? placeholders and passing values separately) so input is always treated as data, not SQL. 


### b) JS Code Injection

> How did you inject JS code?
>
> Could we solve it with CSP?
>
> Does it work on `/users/me`? Why not?
>
> How did you fix the problem?

### c) Access Control

> What do you think about how passwords are currently stored?
>
> How did you improve it?
>
> Explain your access control scheme
>
> Did you add buddies?
>
> Can a user change another users profile info?
 
### d) Security Analysis

> Which project did you review? (Full URL to repository)

> Write you analysis in the [Security Analysis](#security-analysis) section below.


### e) OpenId Connect

> Did you implement OIDC?
> 
> How did you do it?
> 
> Does it work? (it might be difficult for the TAs to test this on their own computers)


## z) Improvements (bonus)

> Did you make any improvements after the main deadline? Make a list of exactly what changes you made.


## å) Chat log (bonus)

> Include your AI chat log in [`AI_LOG.txt`](./AI_LOG.txt)

## MyFace Security Analysis

…
