```md
API Guide
---------

> The service is rolled out **gradually** to all of Apple. Each organization defines their onboarding strategy and process. See additional information on the [onboarding guide](/use/onboarding).

Direct access to the API is designed primarily for tool builders or ML engineers that need to access models directly from script or notebooks. Please check the [tools and integrations](/use/tools) section to explore available tools and integrations.

  

The API is accessible via the [Floodgate proxy](/policy/floodgate), which performs data inspection, logging, and ensures policy compliance.

Supported use cases include:

*   Interactive/online: for example, chat, coding, testing, documentation generation
*   Batch: for example, synthetic data generation, evaluation, auto-grading

Interactive/Online
------------------

### Code example using Python

    import os
    from openai import OpenAI
    
    # Set up the Floodgate authentication token
    TOKEN = os.popen('/usr/local/bin/appleconnect getToken -C hvys3fcwcteqrvw3qzkvtk86viuoqv --token-type=oauth --interactivity-type=none -E prod -G pkce -o openid,dsid,accountname,profile,groups').read().split()[-1]
    client = OpenAI(api_key=TOKEN)
    
    # Base URL for Floodgate API
    client.base_url = 'https://floodgate.g.apple.com/api/openai/v1'
    
    completion = client.chat.completions.create(
        model='aws:anthropic.claude-3-7-sonnet-20250219-v1:0',
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Describe me the solar system formation as a hippy astronaut"}
        ]
    )
    
    print(completion.choices[0].message.content)

### Code example using curl

    export TOKEN=`/usr/local/bin/appleconnect getToken -C hvys3fcwcteqrvw3qzkvtk86viuoqv --token-type=oauth --interactivity-type=none -E prod -G pkce -o openid,dsid,accountname,profile,groups | grep 'oauth-id' | cut -d' ' -f2`

Get list of models:

    curl -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" https://floodgate.g.apple.com/api/openai/v1/models

Access a model:

    curl https://floodgate.g.apple.com/api/openai/v1/chat/completions -H "Content-Type: application/json" -H "Authorization: Bearer ${TOKEN}" -H "User-Agent: API-Example" -d '{
      "model": "aws:anthropic.claude-3-7-sonnet-20250219-v1:0",
      "messages": [
        {
          "role": "system",
          "content": "You are a poetic assistant, skilled in explaining complex programming concepts with creative flair."
        },
        {
          "role": "user",
          "content": "Compose a haiku that explains the value of API reference documentation."
        }
      ]
    }'

> Please use a meaningful User-Agent header in your requests.

Batch
-----

Use cases include:

*   High-volume tasks like synthetic data generation and bulk test creation

Code example in Python:

    import requests
    from os import path
    from urllib import parse
    
    def upload_input(token, input_file):
        resp = requests.post(
          "https://floodgate.g.apple.com/api/batch/v1/inputs",
          headers={"Authorization": f"Bearer {token}"}
        )
        if resp.status_code != 200:
            raise Exception(f"Failed to upload input: got {resp.status_code} from floodgate instead of 200: {resp.text}")
        input_json = resp.json()
        with open(input_file, "rb") as f:
            s3Resp = requests.put(input_json["uri"], data=f)
            if s3Resp.status_code != 200:
                raise Exception(f"Failed to upload input to S3: {resp.text}")
        return input_json["id"]
    
    def create_job(token, input_id):
        create_job_req = {
            "model":"aws:anthropic.claude-3-5-sonnet-20241022-v2:0",
            "input_ids": [input_id],
        }
        resp = requests.post(
          "https://floodgate.g.apple.com/api/batch/v1/jobs",
          headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
          json=create_job_req
        )
        if resp.status_code != 200:
            raise Exception(f"Failed to create job: {resp.text}")
        return resp.json()["id"]
    
    def get_output_urls(token, job_id):
        r = requests.get(
          f"https://floodgate.g.apple.com/api/batch/v1/jobs/{job_id}/outputs",
          headers={"Authorization": f"Bearer {token}" }
        )
        return [output["uri"] for output in r.json() if output["type"] != "manifest"]
    
    def download_output(url, destination):
        parsed_url = parse.urlparse(url)
        r = requests.get(url)
        dest_name = destination + "/" + path.basename(parsed_url.path)
        with open(dest_name, "wb") as f:
            f.write(r.content)
        return dest_name

Error Code

Cause

Mitigation

429

Rate limit exceeded

Implement exponential backoff. [Cost governance](/use/governance)

—

—

—

403

Unauthorized to use the app

Ensure you’ve gone through the onboarding steps

451

Policy violation (e.g., protected code in prompt)

Review input for policy compliance.

503

Gateway timeout

Retry with shorter prompts or split batch requests.

Auth
----

Currently Floodgate supports two forms of authentication: OAuth ID tokens and Narrative Person certificates.

### OAuth ID tokens via the PKCE flow

This is the recommended approach for any interactive workload running on a macOS system.

To quickly get an ID token locally via AppleConnect, perform the following command:

    TOKEN=`appleconnect getToken -t oauth -G pkce -C hvys3fcwcteqrvw3qzkvtk86viuoqv -o openid,dsid,accountname,email,groups --interactivity-type none | grep id-token | cut -d ' ' -f 2`

Then, pass this token as a bearer token to the api as authentication, for example via curl:

    curl -H "Authorization: Bearer ${TOKEN}" -H "User-Agent: API-Example" https://floodgate.g.apple.com/api/openai/v1/completions -d '{"stream": true, "model": "aws:anthropic.claude-3-5-haiku-20241022-v1:0", "prompt": "what is 1 + 1?"}'

> Please use a meaningful User-Agent header in your requests.

### Narrative Person Certificate

You can also authenticate with the API via a Narrative IDMS Person certificate, which is a narrative certificate with an APRN in the form of `aprn:apple:idms:::person:<dsid>`. For more information about these certs, see: [https://narrative.apple.com/using-narrative/idms-identities/#person-identities](https://narrative.apple.com/using-narrative/idms-identities/#person-identities)

In general, once you have the mtls certs available, you should be able to use them via your SDK of choice.

For example: In the OpenAI SDK for Python, you can specify the certs via the HTTP client optional argument:

    client = OpenAI(
        base_url="https://floodgate.g.apple.com/api/openai/v1",
        api_key="floodgate", # currently unused
        http_client=httpx.Client(
          cert=("/path/to/narrative/cert.pem", "path/to/narrative/key.pem"),
        )
    )

Note that the private key may be called “key.pem” or “private.pem” depending on the certificate provider.

Supported API Endpoints
-----------------------

The base URL for general use is [https://floodgate.g.apple.com](https://floodgate.g.apple.com). All of these endpoints require authentication in one of the forms described above.

### OpenAI Interface

We expose these endpoints which are compatible with OpenAI clients.

Major differences

*   Currently only text support is enabled, images or other documents are not allowed.
*   reasoning\_effort is mapped to max tokens internally for anthropic models which support reasoning. This output is returned as a new field in the response called `TODO`

#### Chat Completions

URL: /api/openai/v1/chat/completions

Compatible with the OpenAI Chat endpoint: [https://platform.openai.com/docs/api-reference/chat/create](https://platform.openai.com/docs/api-reference/chat/create)

Unsupported fields:

*   Request
    *   `logit_bias`
    *   `logprobs`
    *   `metadata`, as we don’t expose retrieval APIs
    *   `prediction`
    *   `presence_penalty`
    *   `service_tier`
    *   `store`
    *   `top_logprobs`
    *   `user` (top level field)
    *   `web_search_options`
    *   `seed`
    *   `parallel_tool_calls`
    *   `modalities`
    *   `frequency_penalty`
    *   `audio`
    *   `stream_options.include_usage` (this will always be considered true)
    *   `response_format`
*   Response
    *   `choices[].logprobs`
    *   `service_tier`
    *   `usage.completion_tokens_details`
    *   `usage.prompt_tokens_details`

#### Completions

URL: /api/openai/v1/completions

Compatible with the OpenAI Completions endpoint: [https://platform.openai.com/docs/api-reference/completions/create](https://platform.openai.com/docs/api-reference/completions/create)

Unsupported fields

*   All fields mentioned in chat completions as unsupported
*   Request
    *   `best_of`
    *   `echo`
    *   `n`
    *   `suffix`

#### List Models

URL: /openai/v1/models

Unsupported Fields

*   Response
    *   `owned_by`
    *   `created`

### Messages API

URL: /api/anthropic/v1/messages

Compatible with the Anthropic Messages API: [https://docs.anthropic.com/en/api/messages](https://docs.anthropic.com/en/api/messages)

Major differences

*   Currently only text support is enabled, images or other documents are not allowed.

Unsupported Fields

*   Headers
    *   `anthropic-beta`
    *   `anthropic-version`
    *   `x-api-key`

### Batch API

The batch API is still in development and is not generally available at this time.

TODO: Expand with api details. See the code example above for basic usage information.

Auth Examples
-------------

How you get a narrative certificate depends greatly on the platform you’re currently on, here are some examples:

#### ACI Kube:

For instructions on how to set up narrative certs in your pod, see the `type: idms` section of [https://kube.apple.com/docs/narrative-identities/#](https://kube.apple.com/docs/narrative-identities/).

#### EKS in AWS@Apple:

Based on the tool you used to set up the EKS cluster, there may be more accessible paths for you, but these instructions should be usable by most EKS clusters with some connectivity to Apple. For more information, see [https://github.pie.apple.com/cert-manager/narrative-issuer?tab=readme-ov-file#example-3-pod-identity-transitioned-to-idms-identity](https://github.pie.apple.com/cert-manager/narrative-issuer?tab=readme-ov-file#example-3-pod-identity-transitioned-to-idms-identity)

### Narrative

#### Local

To follow these steps you need AppleConnect 6.2 or greater and you need a narrative cert registered. I’d also recommend installing memento [https://istweb.apple.com/yubikey/](https://istweb.apple.com/yubikey/)

To validate you have a narrative cert, and running `memento show` . This should output at least one line which ends in `aprn:apple:idms:::person:<your_dsid>` . This is a narrative APRN.

In order to create a certificate on disk for a system account, that system account must be setup so that you can use your narrative identity to get a certificate for the system account. To do this, the owner of the system account must go to [appleconnect.apple.com](http://appleconnect.apple.com/) > `Access Policies (Narrative)` on the left bar > Create Access Policy.

The Policy Name box is a name just for you. The APRN field indicates the narrative identity which can request a certificate for your system account. Since we’re doing this at our local desk, this should be in the form `aprn:apple:idms:::person:<your_dsid>` . This should match the output of memento show.

##### Calling floodgate using python

After delegation is configured, you can call floodgate as your system account with the following python snippet:

    pip install apple-narrative

    from openai import OpenAI
    import httpx
    from apple_narrative.config import NarrativeIdentityUDSSource
    from apple_narrative.shortcuts import load_tmp_person_identity
    
    identity = load_tmp_person_identity(
      person_id=1234567,  # system account person ID, replace with your own
      source=NarrativeIdentityUDSSource(kind="actor", domain="idms"),
    )
    client = OpenAI(
      base_url="https://floodgate.g.apple.com/api/openai/v1",
      api_key="EMPTY",
      http_client=httpx.Client(
        cert=(
          identity.key_source.cert_filepath,
          identity.key_source.key_filepath,
          identity.key_source.key_password,
        ),
      ),
    )
    completion = client.chat.completions.create(
        model='aws:anthropic.claude-3-7-sonnet-20250219-v1:0',
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Describe me the solar system formation as a hippy astronaut"}
        ]
    )
    print(completion.choices[0].message.content)

##### Manually retrieving the narrative cert

If you want to fetch the system account certs on disk to call floodgate using curl, etc. then follow these steps:

Using the Apple brew fork, install the narrative-client package (or use any method here: [https://narrative.apple.com/software/](https://narrative.apple.com/software/))

    brew tap narrative/homebrew-tap git@github.pie.apple.com:narrative/homebrew-tap.git
    brew install narrative-client

Then create a file somewhere with the following contents. This file will tell the narrative client how it should request the system account cert. in this case, we’re asking our local apple connect to sign the request with that certificate shown in memento show.

    directory: /tmp/narrative_example
    identities:
      - ref: platform
        unix_socket: AppleConnect
        unmanaged: true
        type: platform
        domain: idms
      - ref: actor
        unix_socket: AppleConnect
        unmanaged: true
        type: actor
        domain: idms
        name: aprn:apple:idms:::person:<your_dsid>
      - ref: system-actor
        type: actor
        domain: idms
        name_json:
          type: person
          person_id: <system_account_dsid>
        identity_attestor: $actor

Finally running `narrative-client <path_to_file_above>` will perform the request for the certificate. If the request succeeded you’ll have a cert pair at /tmp/narrative\_example/system-actor/… . If you don’t see certificates there, the output of the narrative client command might have indicated the error.

#### Turi Bolt

Accessing Floodgate from a bolt task is non-trivial due to the authentication. Below is a guide for creating a bolt task that is capable of reaching Floodgate leveraging narrative certs. Also shown is how to call Floodgate from within a bolt task.

##### Bolt task requirements

1.  your bolt task is running as a system account
    1.  this system account needs to be enrolled to use Floodgate (member of an AD group)
2.  your bolt task is of cluster type AWS or GCP (not the default Kube or simcloud)
3.  you have a whisper namespace (doesnt have to contain any secrets or even be accessible by the system account), this is because narrative on bolt is a beta feature and is tied to whisper: [https://bolt.apple.com/docs/task-secrets.html#beta-leveraging-narrative-in-bolt](https://bolt.apple.com/docs/task-secrets.html#beta-leveraging-narrative-in-bolt)
    1.  the bolt task config should set secrets: {namespace: }
4.  the manager of your system account allows narrative delegation from the turi domain to the idms domain (can be done at [https://appleconnect.apple.com](https://appleconnect.apple.com)) delegate for aprn:apple:turi::notary:person:
    
    1.  WARNING: this allows anyone who presents a narrative cert from the turi domain signed as your system account to get access to your system account idms narrative cert which can be used to generate oidc tokens, etc.
    

##### Code to setup an OpenAI client in the bolt task

Make sure apple-narrative python library is installed:

    pip install apple-narrative

Now create a client:

    from openai import OpenAI
    import httpx
    from apple_narrative.config import NarrativeIdentityFileSource
    from apple_narrative.shortcuts import load_tmp_person_identity
    
    def floodgate_client():
        cert_path = "/turibolt_k8s_mounts/narrative/turi/chain.pem"
        key_path = "/turibolt_k8s_mounts/narrative/turi/private.pem"
    
        if not os.path.exists(cert_path):
            raise FileNotFoundError(f"Certificate file not found: {cert_path}")
        if not os.path.exists(key_path):
            raise FileNotFoundError(f"Key file not found: {key_path}")
    
        identity = load_tmp_person_identity(
            1234567,  # system account person ID, replace with your own
            NarrativeIdentityFileSource(
                cert_filepath=cert_path,
                key_filepath=key_path,
            ),
        )
    
        return openai.OpenAI(
            base_url="https://floodgate.g.apple.com/api/openai/v1",
            api_key="EMPTY",  # this needs to be non-empty, but is not used
            http_client=httpx.Client(
                cert=(
                    identity.key_source.cert_filepath,
                    identity.key_source.key_filepath,
                    identity.key_source.key_password,
                ),
                trust_env=False,  # don't pickup proxy env vars
            ),
        )

Now use the client:

    client = floodgate_client()
    completion = client.chat.completions.create(
        model='aws:anthropic.claude-3-7-sonnet-20250219-v1:0',
        messages=[
            {"role": "system", "content": "You are a helpful assistant."},
            {"role": "user", "content": "Describe me the solar system formation as a hippy astronaut"}
        ]
    )
    
    print(completion.choices[0].message.content)
```