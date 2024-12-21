import os
import base64
import requests
import webbrowser
from loguru import logger
import boto3
import json


def retrieve_secrets(secret_name="SchwabAPI_Credentials", region_name="us-east-2"):
    """Retrieve the current secrets from AWS Secrets Manager."""
    client = boto3.client("secretsmanager", region_name=region_name)
    response = client.get_secret_value(SecretId=secret_name)
    secret_dict = json.loads(response['SecretString'])
    return secret_dict


def update_secrets(new_values, secret_name="SchwabAPI_Credentials", region_name="us-east-2"):
    """Update the secrets in AWS Secrets Manager with new token values."""
    client = boto3.client("secretsmanager", region_name=region_name)
    # Retrieve current secret
    current_secret = retrieve_secrets(secret_name, region_name)
    # Update fields
    for k, v in new_values.items():
        current_secret[k] = v
    # Store updated secret
    client.put_secret_value(
        SecretId=secret_name,
        SecretString=json.dumps(current_secret)
    )
    logger.info("Secret updated successfully.")


def construct_init_auth_url() -> tuple[str, str, str]:
    secret_dict = retrieve_secrets()
    app_key = secret_dict["app-key"]
    app_secret = secret_dict["app-secret"]
    auth_url = f"https://api.schwabapi.com/v1/oauth/authorize?client_id={app_key}&redirect_uri=https://127.0.0.1"

    logger.info("Click to authenticate (opening browser):")
    logger.info(auth_url)

    return app_key, app_secret, auth_url


def construct_headers_and_payload(returned_url, app_key, app_secret):
    # Extract the code from the returned URL
    # The code is between 'code=' and '%40'
    response_code = f"{returned_url[returned_url.index('code=') + 5: returned_url.index('%40')]}@"

    credentials = f"{app_key}:{app_secret}"
    base64_credentials = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")

    headers = {
        "Authorization": f"Basic {base64_credentials}",
        "Content-Type": "application/x-www-form-urlencoded",
    }

    payload = {
        "grant_type": "authorization_code",
        "code": response_code,
        "redirect_uri": "https://127.0.0.1",
    }

    return headers, payload


def retrieve_tokens(headers, payload) -> dict:
    init_token_response = requests.post(
        url="https://api.schwabapi.com/v1/oauth/token",
        headers=headers,
        data=payload,
    )
    init_tokens_dict = init_token_response.json()
    return init_tokens_dict


def main():
    app_key, app_secret, cs_auth_url = construct_init_auth_url()
    webbrowser.open(cs_auth_url)

    logger.info("Paste Returned URL:")
    returned_url = input().strip()

    init_token_headers, init_token_payload = construct_headers_and_payload(
        returned_url, app_key, app_secret
    )

    init_tokens_dict = retrieve_tokens(
        headers=init_token_headers, payload=init_token_payload
    )

    logger.debug(init_tokens_dict)

    # Update the secret in AWS Secrets Manager with the obtained tokens
    update_values = {
        "access_token": init_tokens_dict.get("access_token", ""),
        "refresh_token": init_tokens_dict.get("refresh_token", "")
    }
    update_secrets(update_values)

    return "Done!"


if __name__ == "__main__":
    main()
