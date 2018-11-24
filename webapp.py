from flask import Flask, request, Response, make_response
app = Flask(__name__)
#
# Flask entry points
#
@app.route('/', defaults={'path': ''},  methods = ['GET', 'POST', 'PUT', 'DELETE'])
def handle_all(path):
    r1 = 'Request method: {} {}'.format(request.method, path)
    r2 = 'Request headers: {} bytes'.format(len(request.headers))
    r3 = 'Body: {} bytes'.format(request.content_length)
    print(r1 + '\n' + r2 + '\n' + r3 + '\n')
    return r1 + '<br>' + r2 + '<br>' + r3 + '<br>'

# Start the app
if __name__ == "__main__":
    app.run()