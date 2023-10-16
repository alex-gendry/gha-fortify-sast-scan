import * as core from '@actions/core'
import * as exec from '@actions/exec'

/**
 * Generate the HTTP body for creating an SSC Application Version
 * Application can be either provided by id (if it exists), or by name (if it does not exists)
 * @param app The application name or id
 * @param version The version name
 * @returns {any} returns the HTTP body as JSON object
 */
export function getCreateAppVersionBody(app: any, version: string): any {
  const bodyJson = JSON.parse(`
    {
        "name": "${version}",
        "description": "",
        "active": true,
        "committed": false,
        "project": {
        }
    }`)

  switch (typeof app) {
    case 'string':
      bodyJson['project']['name'] = app
      break
    case 'number':
      bodyJson['project']['id'] = app
      break
    default:
      core.error(
        `app parameter should be of type string or number. Not: ${typeof app}`
      )
      core.setFailed('AppVersion HTTP body creation failed')
  }

  return bodyJson
}

/**
 * Generate the HTTP body for SSC Application Version Copy State
 * @param source The source application Version id
 * @param target The target application Version id
 * @returns {any} returns the HTTP body as JSON object
 */
export function getCopyStateBody(source: string, target: string): any {
  const bodyJson = JSON.parse(`
        {
            "copyAnalysisProcessingRules": "true",
            "copyBugTrackerConfiguration": "true",
            "copyCustomTags": "true",
            "previousProjectVersionId": "${source}",
            "projectVersionId": "${target}"
        }`)

  return bodyJson
}

/**
 * Generate the HTTP body for SSC Application Version Copy Vulns
 * @param source The source application Version id
 * @param target The target application Version id
 * @returns {any} returns the HTTP body as JSON object
 */
export function getCopyVulnsBody(source: string, target: string): any {
  const bodyJson = JSON.parse(`
          {
              "previousProjectVersionId": "${source}",
              "projectVersionId": "${target}"
          }`)

  return bodyJson
}

/**
 * Generate the full path to the fcli executable, depending on the env variables :
 *  FCLI_EXECUTABLE_PATH
 *  FCLI_EXECUTABLE_LOCATION
 * @returns {any} returns the full path to fcli
 */
export function getFcliPath(): string {
  if (process.env.FCLI_EXECUTABLE_PATH) {
    return `${process.env.FCLI_EXECUTABLE_PATH.replace(/\/+$/, '')}`
  } else if (process.env.FCLI_EXECUTABLE_LOCATION) {
    return `${process.env.FCLI_EXECUTABLE_LOCATION.replace(/\/+$/, '')}/fcli`
  } else {
    return 'fcli'
  }
}

/**
 * Generate the full path to the scancentral executable, depending on the env variables :
 *  SC_EXECUTABLE_PATH
 *  SC_EXECUTABLE_LOCATION
 * @returns {any} returns the full path to scancentral
 */
export function getScanCentralPath(): string {
  if (process.env.SC_EXECUTABLE_PATH) {
    return `${process.env.SC_EXECUTABLE_PATH.replace(/\/+$/, '')}`
  } else if (process.env.SC_EXECUTABLE_LOCATION) {
    return `${process.env.SC_EXECUTABLE_LOCATION.replace(
      /\/+$/,
      ''
    )}/scancentral`
  } else {
    return 'scancentral'
  }
}

export async function fcli(args: string[]): Promise<any> {
  core.debug('fcli START')
  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: true
  }

  core.debug('fcli begin')
  const response = await exec.exec(getFcliPath(), args, options)
  core.debug(responseData)
  core.debug(errorData)

  return JSON.parse(responseData)
}

export async function scancentral(args: string[]): Promise<any> {
  let responseData = ''
  let errorData = ''

  const options = {
    listeners: {
      stdout: (data: Buffer) => {
        responseData += data.toString()
      },
      stderr: (data: Buffer) => {
        errorData += data.toString()
      }
    },
    silent: false
  }

  const response = await exec.exec(getScanCentralPath(), args, options)
  core.debug(responseData)
  core.debug(`response=${response}`)

  return response
}
