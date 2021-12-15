from flask import Flask, render_template, request
import encryption.RSA as rsa
import array
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
        data = ''
        p = 0
        q = 0
        key = ''
        msg = ''
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

    return render_template('RSA.html', output=json.dumps(output), is_ext_vignere = True)
# def RSA():
#     enk_shitt = ""
#     dek_shitt = ""
#     if request.method == "POST":
#         p = con.conint(request.form.get("key_enc"))
#         q = con.conint(request.form.get("key_dec"))
#         text_enk = request.form.get("text_enc")
#         text_dek = request.form.get("text_dec")
#         if key_enk != -1:
#             enk_shitt = enc_shitt.encrypt_shitt(text_enk, key_enk)
#         if key_dek != -1:
#             dek_shitt = dec_shitt.decrypt_shitt(text_dek, key_dek)
#         return render_template("RSA.html", content=[enk_shitt, dek_shitt] , is_shift = 'yes')
#     else:
#         return render_template("RSA.html", content=[enk_shitt, dek_shitt], is_shift = 'yes')

@app.route("/ecc", methods=['POST', 'GET'])
def ecc():
    enk_subsitution = ""
    dek_subsitution = ""
    if request.method == "POST":
        key_enk = con.constring(request.form.get("key_enc"))
        key_dek = con.constring(request.form.get("key_dec"))
        text_enk = request.form.get("text_enc")
        text_dek = request.form.get("text_dec")
        if key_enk != -1:
            enk_subsitution = enc_substitution.encrypt_subsitution(text_enk, key_enk)
        if key_dek != -1:
            dek_subsitution = dec_substitution.decrypt_subsitution(text_dek, key_dek)
        return render_template("Subtitutioncipherstandard.html", content=[enk_subsitution, dek_subsitution], is_substitution = 'yes')
    else:
        return render_template("Subtitutioncipherstandard.html", content=[enk_subsitution, dek_subsitution], is_substitution = 'yes')

@app.route("/ntru", methods=['POST', 'GET'])
def ntru():
    enk_subsitution = ""
    dek_subsitution = ""
    if request.method == "POST":
        key_enk = con.constring(request.form.get("key_enc"))
        key_dek = con.constring(request.form.get("key_dec"))
        text_enk = request.form.get("text_enc")
        text_dek = request.form.get("text_dec")
        if key_enk != -1:
            enk_subsitution = enc_substitution.encrypt_subsitution(text_enk, key_enk)
        if key_dek != -1:
            dek_subsitution = dec_substitution.decrypt_subsitution(text_dek, key_dek)
        return render_template("Subtitutioncipherstandard.html", content=[enk_subsitution, dek_subsitution], is_substitution = 'yes')
    else:
        return render_template("Subtitutioncipherstandard.html", content=[enk_subsitution, dek_subsitution], is_substitution = 'yes')

if __name__ == "__name_-":
    app.run()
