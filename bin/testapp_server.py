#!/usr/bin/env python

from optparse import OptionParser
import logging

from testapp import app

opt_parser = OptionParser(conflict_handler="resolve")
opt_parser.add_option("-h", "--host",
                      dest="host",
                      default='127.0.0.1',
                      metavar='HOST',
                      help="Listen on this IP (use 0.0.0.0 for all)")
opt_parser.add_option("-p", "--port",
                      dest="port",
                      type=int,
                      default=5000,
                      metavar='PORT',
                      help="Listen on this port")
cmdline_opts, _ = opt_parser.parse_args()

logging.getLogger().addHandler(logging.StreamHandler())
logging.getLogger().setLevel(logging.DEBUG)

app.run(debug=True, host=cmdline_opts.host, port=cmdline_opts.port)
