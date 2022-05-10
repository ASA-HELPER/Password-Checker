#PASSWORD CHECKER PROJECT: In this project, we are checking that how many times your password was hacked and whether it's secure or not.
#Run this project on Visual Studio Code and then terminal window opens and just write the passoword in it to test it.
#Here we are using the concept of SHA1 hashing algorithm whcich is a tool coverting the password into uppercase hexadecimal hash.
#Here the api uses a techinque known as K anonymity which somebody allow to receive information about us, yet still not no we are.
import requests                                      #This module is imported to requests data from the browser.
import hashlib                                       #This library is imported to use SHA1 hashing.
import sys

#Here we make a function which asks for the data from the api.
def requests_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f'Error fetching: {res.status_code}, please check the Api and try again.')
    return res
#Here we make a function which receives hashes and loop through all hashes to match with hash of our password. the splitlines method is used to return 
# a list of lines in the string, bresking at line boundaries.
def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h==hash_to_check:
            return count
    return 0

#Here we make a function which uses SHA1 algorithm and checks password if it exists in API response.The hexdigest method used here returns a string of 
# double length, containing only hexadecimal digits.This may be used to exchange the value safely in email or other non-binary environments.
#if hexdigest method does not used here then we get the hashed object of our password.And we are using upper case the hexadecimal digits because the 
# SHA1 algorithm returns the hashed password in uppercase.
#if you don't you use encode('utf-8') then you will get a TypeError: Unicode objects must be encoded before hashing. 
#You can print the response and first5_char and tail by adding the print statement to check whether you are getting the right response or not.
#You can read the responses by API using the statement:print(response.text) in the function below.
def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = requests_api_data(first5_char)
    return get_password_leaks_count(response, tail)

def main(args):
    for password in args:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was not found. Carry on!')
    return 'Done!'
if __name__ =='__main__':
    sys.exit(main(sys.argv[1:]))    
    
#Here we are using exit method to exit the process in case for some reason the output on command line does not exit or just to make sure that 
# the system call actually exit and brings ud back to the command line.