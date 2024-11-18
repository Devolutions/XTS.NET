# Test cases generator
This generator takes the test vectors specified in the IEEE1619-2018 standard and generates test cases for the library.  
For copyright reasons, we cannot provide the input file itself.

## How to use
### Setup
First, install the required dependencies:
```sh
pip install -r ./requirements.txt
```

Then, copy and paste the test vectors from the standard into a text file named `test_case_input.txt`. Then, remove the irrelevant lines(section headers, headers, footers, etc.) and make sure the file ends with a newline, or else the last test case will not be captured by the regex. 

### Run
Run the following command:
```sh
python ./test_case_gen.py
```