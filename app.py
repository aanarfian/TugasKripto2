from flask import Flask, render_template, request
import encryption.RSA as rsa
import encryption.ECC as ecc
import encryption.NTRU as ntru
import json


app = Flask(__name__)
app.config['TEMPLATES_AUTO_RELOAD'] = True

@app.route("/", methods=['GET'])
def home():
    return render_template("index.html", is_home= 'yes')

@app.route("/rsa", methods=['POST', 'GET'])
def RSA():
    output = {}

    if request.method == "POST":
        data,p,q,key = None,None,None,None

        op_type = request.args.get("type")

        print(op_type)

        if op_type == "genkey":
            p = request.form.get("p")
            q = request.form.get("q")
            output["type"] = "genkey"
            output["result"] = rsa.genkey(p, q)
        elif op_type == "enc":
            key = request.form.get("key")
            data = request.form.get("data")
            key = list(map(int, key.split()))
            print(data)
            print(key)
            output["type"] = "enc"
            output["result"] = rsa.encrypt(data, key[0], key[1])
            # while 1:
            #     continue
        else:
            key = request.form.get("key")
            data = request.form.get("data")
            key = list(map(int, key.split()))
            data = list(map(int, data.split(',')))
            print(key)
            output["type"] = "dec"
            output["result"] = rsa.decrypt(data, key[0], key[1])

    return render_template('RSA.html', output=json.dumps(output), is_rsa = True)

@app.route("/ecc", methods=['POST', 'GET'])
def ECC():
    output = {}
    if request.method == "POST":
        data,key = None,None
        op_type = request.args.get("type")
        print(op_type)

        if op_type == "genkey":
            output["type"] = "genkey"
            output["result"] = ecc.genkey()
            print(output["result"])
        elif op_type == "enc":
            key = request.form.get("key")
            data = request.form.get("data")
            key = list(map(int, key.split()))
            print(data)
            print(key)
            output["type"] = "enc"
            output["result"] = ecc.encrypt(data, key[0], key[1])
            print(output["result"])
            # while 1:
            #     continue
        else:
            key = request.form.get("key")
            data = request.form.get("data")
            key = int(key)
            data = list(map(int, data.split(',')))
            print('data', data)
            print('key', key)
            output["type"] = "dec"
            output["result"] = [(ecc.decrypt(data[0], data[1], data[2], data[3], key)).decode('utf-8')]
            print(output["result"])

    return render_template('ECC.html', output=json.dumps(output), is_ecc = True)

@app.route("/ntru", methods=['POST', 'GET'])
def NTRU():
    output = {}
    if request.method == "POST":
        data,key = None,None
        op_type = request.args.get("type")
        print(op_type)

        if op_type == "genkey":
            output["type"] = "genkey"
            output["result"] = ntru.genkey()
            print(output["result"])
        elif op_type == "enc":
            # while 1:
            #     continue
            key = request.form.get("key")
            data = request.form.get("data")
            key = key.replace(',', '\n')
            output["type"] = "enc"
            output["result"] = ntru.encryptntru(data, key)
            print(output["result"])
        else:
            key = request.form.get("key")
            data = request.form.get("data")
            key = key.replace(',', '\n')
            output["type"] = "dec"
            output["result"] = ntru.decryptntru(data, key)
            print(output["result"])

    return render_template('NTRU.html', output=json.dumps(output), is_ntru = True)

# @app.route("/ntru", methods=['POST', 'GET'])
# def ntru():
#     enk_subsitution = ""
#     dek_subsitution = ""
#     if request.method == "POST":
#         key_enk = con.constring(request.form.get("key_enc"))
#         key_dek = con.constring(request.form.get("key_dec"))
#         text_enk = request.form.get("text_enc")
#         text_dek = request.form.get("text_dec")
#         if key_enk != -1:
#             enk_subsitution = enc_substitution.encrypt_subsitution(text_enk, key_enk)
#         if key_dek != -1:
#             dek_subsitution = dec_substitution.decrypt_subsitution(text_dek, key_dek)
#         return render_template("Subtitutioncipherstandard.html", content=[enk_subsitution, dek_subsitution], is_substitution = 'yes')
#     else:
#         return render_template("Subtitutioncipherstandard.html", content=[enk_subsitution, dek_subsitution], is_substitution = 'yes')

if __name__ == "__name_-":
    app.run()
