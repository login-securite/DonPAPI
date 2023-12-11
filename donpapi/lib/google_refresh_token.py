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

def refreshToken2(client_id, client_secret, refresh_token):
        params = {
                "grant_type": "refresh_token",
                "client_id": client_id,
                "client_secret": client_secret,
                "refresh_token": refresh_token
        }

        authorization_url = "https://www.googleapis.com/oauth2/v4/token"

        r = requests.post(authorization_url, data=params)
        print(r.content)
        if r.ok:
                print(f"access_token:{r.json()['access_token']}")
                print(f"scope:{r.json()['scope']}")
                print(f"id_token:{r.json()['id_token']}")
                return r.json()['access_token']
        else:
                return None

def get_decryption_key():
        #https://devicepasswordescrowforwindows-pa.googleapis.com/v1/getprivatekey/<resource_id >
        #Todo
        #https://www.bitdefender.com/blog/businessinsights/the-chain-reaction-new-methods-for-extending-local-breaches-in-google-workspace/
        return 1


def main():

    parser = argparse.ArgumentParser(add_help = True, description = "Get Google Service Token")

    parser.add_argument('-d','--debug', action='store_true', help='Turn DEBUG output ON')
    parser.add_argument('-t', '--token', help='token')

    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()
    client_id = '77185425430.apps.googleusercontent.com'
    client_secret = 'OTJgUOQcT7lO7GsGZq2G4IlT'
    refresh_token = options.token
    rt=refreshToken2(client_id, client_secret, refresh_token)
    print(f'{rt}')
    return rt


if __name__ == "__main__":
        main()
