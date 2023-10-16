import * as utils from './utils'
import * as core from '@actions/core'

export async function packageSourceCode(buildOpts: string): Promise<number> {
  return await utils.scancentral(['package', buildOpts])
}
