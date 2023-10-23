import * as core from "@actions/core";
import * as utils from "./utils";

export async function commitCustomTagExists(guid: string): Promise<boolean> {
    core.debug(`Checking if CustomTag ${guid} exists`)

    let {
        data: data,
        count: count,
        responseCode: responseCode,
        links: links
    } = await utils.fcliRest(`/api/v1/customTags?q=guid:${guid}`)
    core.debug(responseCode)

    if (200 <= Number(responseCode) && Number(responseCode) < 300) {
        if (count != 0) {
            core.debug(`Custom tag ${guid} found : ${data[0].name}`)
            return true
        }
        return false
    } else {
        core.error(`commitCustomTagExists failed with code ${responseCode}`)
        return false
    }
}