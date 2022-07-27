# ci_cd_test
This repo contains script which mimics CI/CD and includes security scan stage in it, which uses `semgrep` and `detect-secrets` tools for static code analysis

## Prerequisites
To run the scrip you need Git, Docker, Python3 and Pip3 installed.


To install scanners run:
```
# clone the repo
git clone https://github.com/serhiizaidlin/ci_cd_test
# install requirements
cd ci_cd_test
pip3 install -r requirements.txt
```

## Usage
### Initial build
This script uses https://github.com/serhiizaidlin/sample-nodejs as a target for scanning and building test app. You don't need to clone this repo, all work is done by CI/CD script.

To start the script, being in `ci_cd_test` dir, run:
```
python3 script.py
```
This wil build a docker image for `sample-nodejs` app and run it in a container. App would be available at http://localhost:3333

### Testing security tools
This repo contains a vulnerable file `insecure.js`. To test it run:
```
cp insecure.js ./sample-nodejs
python3 script.py
```
The script will write scan results to `stdout` and fail build.
