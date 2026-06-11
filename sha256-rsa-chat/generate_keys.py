import rsa

julia_pub, julia_priv = rsa.generate_keys()
lucas_pub, lucas_priv = rsa.generate_keys()

rsa.save_key(lucas_priv, "lucas_priv.key")
rsa.save_key(julia_priv, "julia_priv.key")
rsa.save_key(lucas_pub, "lucas_pub.key")
rsa.save_key(julia_pub, "julia_pub.key")

print("Chaves criptográficas criadas com sucesso.")