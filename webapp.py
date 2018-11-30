import configparser
from flask import Flask, request, jsonify
from readSMIMEsig import createLogger, read_smime_email

app = Flask(__name__)

class InvalidUsage(Exception):
    """
    Error handler - see http://flask.pocoo.org/docs/1.0/patterns/apierrors/
    """
    status_code = 400

    def __init__(self, message, status_code=None, payload=None):
        Exception.__init__(self)
        self.message = message
        if status_code is not None:
            self.status_code = status_code
        self.payload = payload

    def to_dict(self):
        rv = dict(self.payload or ())
        rv['message'] = self.message
        return rv


@app.errorhandler(InvalidUsage)
def handle_invalid_usage(error):
    response = jsonify(error.to_dict())
    response.status_code = error.status_code
    return response


@app.route('/', methods = ['POST'])
def handle_inbound_relay():
    """
    Flask application entry point.
    """
    logfile = 'webapp.log'
    logger = createLogger(logfile)
    logger.info('Request from {}, scheme={}, path={}'.format(request.remote_addr, request.scheme, request.path))
    logger.info('| Headers: {}, Body: {} bytes'.format(len(request.headers), request.content_length))

    # Check request data format, header token value is correct (if present)
    if request.content_type != 'application/json':
        logger.info('| Unknown Content-Type: {}'.format(request.content_type))
        raise InvalidUsage('Unknown Content-Type in request headers')

    config = configparser.ConfigParser()
    config.read('webapp.ini')
    cfg = config['webapp']

    expected_token = cfg.get('x-messagesystems-webhook-token')
    got_token = request.headers['X-MessageSystems-Webhook-Token']
    if expected_token != None:
        if got_token != expected_token:
            logger.info('| Invalid X-MessageSystems-Webhook-Token in request headers: {}, must match {}'.format(got_token, expected_token))
            raise InvalidUsage('Invalid X-MessageSystems-Webhook-Token in request headers')

    req = request.get_json()
    for i in req:
        m = i['msys']['relay_message']
        c = m['content']
        rxMail = c['email_rfc822'].encode('utf8')
        logger.info('| msg_from={}, rcpt_to={}, email_rfc822: {} bytes'.format(m['msg_from'], m['rcpt_to'], len(rxMail)))
        read_smime_email(rxMail, logger)

    return 'OK'

# Start the app
if __name__ == "__main__":
    app.run()