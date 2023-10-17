import * as utils from './utils'
import * as core from '@actions/core'

export async function packageSourceCode(buildOpts: string): Promise<number> {
  return await utils.scancentral(
    ['package'].concat(
      utils.stringToArgsArray(buildOpts).concat(['-o', 'package.zip'])
    )
  )
}

export async function startSastScan(
  app: string,
  version: string
): Promise<string> {
  let jsonRes = await utils.fcli([
    'sc-sast',
    'scan',
    'start',
    '--upload',
    `--appversion=${app}:${version}`,
    `--sensor-version=23.1.0`,
    `--package-file=package.zip`,
    '--output=json'
  ])

  if (jsonRes['__action__'] == 'SCAN_REQUESTED') {
    core.debug(`Scan ${jsonRes['jobToken']} requested`)
    return jsonRes['jobToken']
  } else {
    throw new Error(
      `Scan submission failed: Fortify returned ${jsonRes['__action__']}`
    )
  }
}

// export async function waitForSastScan(jobToken: string): Promise<string> {
//   let jsonRes = await utils.fcli([
//     'sc-sast',
//     'scan',
//     'start',
//     '--upload',
//     `--appversion=${app}:${version}`,
//     `--sensor-version=23.1.0`,
//     `--package-file=package.zip`,
//     '--output=json'
//   ])
//
//   if (jsonRes['__action__'] == 'SCAN_REQUESTED') {
//     core.debug(`Scan ${jsonRes['jobToken']} requested`)
//     return jsonRes['jobToken']
//   } else {
//     throw new Error(
//       `Scan submission failed: Fortify returned ${jsonRes['__action__']}`
//     )
//   }
// }
