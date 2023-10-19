# Create Application Version in Fortify Software Security Center

Build secure software fast with [Fortify](https://www.microfocus.com/en-us/solutions/application-security). Fortify offers end-to-end application security solutions with the flexibility of testing on-premises and on-demand to scale and cover the entire software development lifecycle.  With Fortify, find security issues early and fix at the speed of DevOps.

This GitHub Action utilizes [fcli](https://github.com/fortify/fcli) to create an Application Version in Fortify Software Security Center.
The Action can copy the Application State and the Values from another Application version

## Table of Contents


* [Requirements](#requirements)
    * [SSC instance](#ssc-instance)
    * [Network connectivity](#network-connectivity)
    * [fcli](#fcli)
* [Usage](#usage)
    * [Create Application Version](#create-application-version)
        * [Create Application Version with Copy State and Vulns](#create-application-version-with-copy-state-and-vulns)
        * [SSC Inputs](#ssc-inputs)
* [Environment Variables](#environment-variables)
* [Information for Developers](#information-for-developers)

## Requirements

### SSC instance
Obviously you will need to have an SSC instance from which you can retrieve Fortify scan results. If you are not already a Fortify customer, check out our [Free Trial](https://www.microfocus.com/en-us/products/application-security-testing/free-trial).

### Network connectivity
The SSC instance in which you want to create an Application Version needs to be accessible from the GitHub Runner where this action is being executed. Following table lists some considerations:

| Source | Runner        | Considerations |
| ------ | ------------- | -------------- |
| SSC    | GitHub-hosted | GitHub lists [IP addresses for GitHub-hosted runners](https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners#ip-addresses) that need to be allowed network access to SSC. Exposing an SSC instance to the internet, even if limited to only GitHub IP addresses, could pose a security risk. |
| SSC    | Self-hosted   | May need to allow network access from the self-hosted runner to SSC if in different network segments |

### fcli

This action uses [fcli](https://github.com/fortify/fcli) for most of its call to Software Security Center. Either use the [OpenText Official Docker Image](https://hub.docker.com/r/fortifydocker/fortify-ci-tools): `
fortifydocker/fortify-ci-tools`. Or download the cli in you jobs:

```bash
  - name: Download fcli
    run: |
      wget -qO- https://github.com/fortify/fcli/releases/download/v1.3.1/fcli-linux.tgz | tar zxf -  
```

## Usage

The primary use case for this action is before the execution of a Fortify scan. See the [Fortify ScanCentral Scan](https://github.com/marketplace/actions/fortify-scancentral-scan) action for more details on how to initiate SAST scans on Fortify ScanCentral SAST.


### Create Application Version

This example workflow demonstrates how to create an application version in SSC, using the repo and branch names as app:version

```yaml
name: (FTFY) Create Application Version
on: [workflow dispatch]
      
jobs:                                                  
  CreateAppVersion:
    runs-on: ubuntu-latest
    
    container:
      image: fortifydocker/fortify-ci-tools

    steps:
      # Pull SAST issues from Fortify on Demand and generate GitHub-optimized SARIF output
      - name: Create Application Version
        uses: agendry-pub/gha-ssc-create-application-version@v1
        with:
          ssc_url: ${{ vars.FTFY_SSC_URL}}
          ssc_ci_token: ${{ secrets.FTFY_CI_TOKEN_DEC }}
          ssc_app: ${{ github.event.repository.name }}
          ssc_version: ${{ github.ref_name }}
      
```

#### SSC Considerations

* FCLI supports Fortify Token in Decoded and Encoded format
* Username and Password are required to copy the application version state from another one. The CI Token does not have the required permissions. Unified Login Token is the only type of token, but has a maximum expiration of 1 day

#### Create Application Version with Copy State and Vulns

This example workflow demonstrates how to create an application version in SSC, and copying the Rule, Tags and Vulns from a source application version

```yaml
name: (FTFY) Create Application Version
on: [workflow dispatch]

jobs:
  CreateAppVersion:
    runs-on: ubuntu-latest

    container:
      image: fortifydocker/fortify-ci-tools

    steps:
      # Pull SAST issues from Fortify on Demand and generate GitHub-optimized SARIF output
      - name: Create Application Version
        uses: agendry-pub/gha-ssc-create-application-version@v1
        with:
          ssc_url: ${{ vars.FTFY_SSC_URL}}
          ssc_ci_username: ${{ secrets.FTFY_CI_USERNAME }}
          ssc_ci_password: ${{ secrets.FTFY_CI_PASSWORD }}
          ssc_app: ${{ github.event.repository.name }}
          ssc_version: ${{ github.ref_name }}
          ssc_source_app: ${{ github.event.repository.name }}
          ssc_source_version: main
          copy_vulns: true
          
```

#### SSC Considerations

* if you specify the source app:version, only the Rules, Tags and BugTracker settings will be copied. Set `copy_vulns` to `true`if you want to copy the Vulnerability as well

#### SSC Inputs

**`ssc_url`**  
*Required* The base URL for the Fortify Software Security Center instance where your data resides.

**`ssc_ci_token` OR `ssc_ci_username` + `ssc_ci_password`**  
*Required* Credentials for authenticating to Software Security Center. If both methods provided, the Action will choose the Token. Strongly recommend use of GitHub Secrets for credential management.

**`ssc_app`**  
*Required* The target SSC application name to create

**`ssc_version`**  
*Required* The target SSC application version name to create

**`ssc_source_app`**  
*Optional* The source SSC application name to copy from

**`ssc_source_version`**  
*Optional* The source SSC application version name to copy from

**`copy_vulns`**  
*Optional* Enable to copy vulnerabilities from source to target application version

## Environment Variables

**`FCLI_DEFAULT_TOKEN_EXPIRE`**  
*Optional* Overrides default sessions token lifespan/expiration. Specifies for how long the session should remain active, for example 1h (1 hour), 1d (1 day) \
Default: 1d

## Information for Developers

All commits to the `main` branch should follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) convention. In particular, commits using the `feat: Some feature` and `fix: Some fix` convention are used to automatically manage version numbers and for updating the [CHANGELOG.md](https://github.com/fortify/gha-export-vulnerabilities/blob/master/CHANGELOG.md) file.

Whenever changes are pushed to the `main` branch, the [`.github/workflows/publish-release.yml`](https://github.com/fortify/gha-ssc-create-application-version/blob/main/.github/workflows/publish-release.yml) workflow will be triggered. If there have been any commits with the `feat:` or `fix:` prefixes, the [`release-please-action`](https://github.com/google-github-actions/release-please-action) will generate a pull request with the appropriate changes to the CHANGELOG.md file and version number in `package.json`. If there is already an existing pull request, based on earlier feature or fix commits, the pull request will be updated.

Once the pull request is accepted, the `release-please-action` will publish the new release to the GitHub Releases page and tag it with the appropriate `v{major}.{minor}.{patch}` tag. The two `richardsimko/update-tag` action instances referenced in the `publish-release.yml` workflow will create or update the appropriate `v{major}.{minor}` and `v{major}` tags, allowing users to reference the action by major, minor or patch version.
