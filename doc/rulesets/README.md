# rulesets syntax

The image speciffcation change is based on regularExpretion syntax (see [Regular Expression HOWTO](https://docs.python.org/3/howto/regex.html#regex-howto) or [Python RegEx](https://www.w3schools.com/python/python_regex.asp)).





The ruleset has following syntax:

Each ruleset line consists of three mandatory fields, separated by double colons, and may include an optional comment following a hash sign. The third field can be empty, set to "stop," or contain any other value:  

`pattern::replace::[stop|any-word][ #comment if you wish]`



The webhook processes each line one by one, checking if the pattern matches the current image definition. If it matches, the webhook changes the image according to the replace field and proceeds to the next line or stops if the last field equals the word "stop."

Here’s an example:



    ^(my.harbor.local/.+)::\1::stop # step 1
    ^([^/]+)$::my.harbor.local/docker.io/\1::stop #  step 2
    ^([^\./]+/.+)$::my.harbor.local/docker.io/\1::stop # step 3
    ^(.+)$::my.harbor.local/\1::cont # step 4
    ^([^/]+)/([^:]+):[0-9]+/(.+)::\1/\2/\3::stop # step 5





###### step 1

Check if the image definition starts with my harbor name (my.harbor.local).

If it does, do nothing, leave the image unchanged, and stop.

If the pattern does not match the image, go to the next step.

###### step 2

Check if the image definition does not have slashes (/).

If it is true, add "my.harbor.local/docker.io/" at the beginning of the image name and stop processing.

For example:

`nginx:v10` replaces to `my.harbor.local/docker.io/nginx:v10`



If the pattern does not match the image, go to the next step.



###### step 3

Check if the image definition does not have a dot (.) before the first slash (/).

If it is true, add "my.harbor.local/docker.io/" at the beginning of the image name and stop processing.

For example:

`bitnami/nginx:v10` changes to  `my.harbor.local/docker.io/bitnami/nginx:v10`

If the pattern does not match the image, go to the next step.



###### step 4

For everything else, add "my.harbor.local/" at the beginning and continue to the next step.

For example:

`docker.io/python:3-alpine` will be changed to `my.harbor.local/docker.io/python:3-alpine`

`harbor.examle.com:5000/python:3-alpine` will be changed to `my.harbor.local/harbor.example.com:5000/python:3-alpine` (witch is not a valid image name)

Because the last field of the rule is not equal to "stop," the webhook will proceed to the next rule (step 5).



###### step 5

This rule checks if there is a string ":[0-9]+" after the first slash; if it is, the string is removed.

In our example:

`my.harbor.local/harbor.example.com:5000/python:3-alpine` will be changed to `my.harbor.local/harbor.example.com/python:3-alpine`






