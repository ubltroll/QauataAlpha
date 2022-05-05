from rainbow import RainbowCrypto

def test_rainbow_crypto():
    message= b'test'
    rb = RainbowCrypto.new()
    sig = rb.sign_message(message)
    assert rb.verify_message_signature(message, sig)