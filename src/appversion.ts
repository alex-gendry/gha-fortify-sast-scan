import * as utils from './utils'
import * as core from '@actions/core'

export async function getAppVersionId(
  app: string,
  version: string
): Promise<number> {
  let jsonRes = await utils.fcli([
    'ssc',
    'appversion',
    'ls',
    `-q=application.name=${app}`,
    `-q=name=${version}`,
    '--output=json'
  ])

  if (jsonRes.length === 0) {
    core.debug(`AppVersion "${app}":"${version}" not found`)
    return -1
  } else {
    core.debug(`AppVersion "${app}":"${version}" exists`)
    return jsonRes[0].id
  }
}

export async function appVersionExists(
  app: string,
  version: string
): Promise<boolean> {
  let jsonRes = await utils.fcli([
    'ssc',
    'appversion',
    'ls',
    `-q=application.name=${app}`,
    `-q=name=${version}`,
    '--output=json'
  ])

  if (jsonRes.length === 0) {
    return true
  } else {
    return false
  }
}
