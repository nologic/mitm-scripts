from libmproxy.protocol.http import decoded

import argparse
import logging
import json

def start(context, argv):
    parser = argparse.ArgumentParser(prog="selectors", description="Find selectors in HTTP requests/responses")
    parser.add_argument('-r', '--requests', dest='requests', action='store_true', help="Scan requests")
    parser.add_argument('-p', '--responses', dest='responses', action='store_true', help="Scan responses")
    parser.add_argument('-j', '--json', dest='json', type=str, help="Define selectors", required=True)
    parser.add_argument('-a', '--app', dest='app', help="Appname", required=True)

    argv.pop(0)
    args = parser.parse_args(argv)

    logging.basicConfig(format="[%(asctime)-15s] " + args.app + " %(message)s", filename="mitm.log")
    logger = logging.getLogger("events")
    logger.setLevel(10)

    json_sel = json.loads(open(args.json).read())
    
    context.selectors = json_sel
    context.logger = logger
    context.scan_requests = args.requests
    context.scan_responses = args.responses


def process_string(context, string, flow):
    for k in context.selectors.keys():
        selectors = context.selectors[k]

        for sel in selectors:
            index = string.find(sel.encode("utf8"))
            if(index >= 0):
                logString = "%s|Found '%s' in %s" % (flow.request.host + flow.request.path, k, string[max(index - 10, 0):min(index + 20, len(string))])

                context.log(logString)
                context.logger.info(logString)

def request(context, flow):
    if(context.scan_requests):
        with decoded(flow.request):  # automatically decode gzipped responses.
            process_string(context, flow.request.content, flow)

def response(context, flow):
    if(context.scan_responses):
        with decoded(flow.response):  # automatically decode gzipped responses.
            process_string(context, flow.response.content, flow)