The Lewi-Wu comparison-revealing encryption scheme produces ciphertexts that have two distinct parts, which are referred to as the "left" and "right" ciphertext.
These two ciphertext parts have different properties and uses, and as such must be carefully understood and used correctly to maximise the security of the system that uses Cretrit.


# The "Left" Ciphertext

This ciphertext is *deterministic*; that is, if the same value is encrypted with the same key multiple times, the resulting left ciphertexts will be identical every time.
If an attacker obtains a whole pile of them, they can possibly figure out what the values are, or at least approximately what they are, by performing what is known as an [inference attack](https://en.wikipedia.org/wiki/Inference_attack).
Preferably, then, you shouldn't store left ciphertexts if you can avoid them.

This deterministic nature of the left ciphertexts allows the ability to determine if values are equal, but if they're not equal, left ciphertexts by themselves are not enough to determine anything else about two values.
To get any other comparison information, you need to compare a left ciphertext against a right ciphertext.


# The "Right" Ciphertext

This ciphertext is *non-deterministic*; that is, if the same value is encrypted with the same key multiple times, the resulting right ciphertexts will be totally different, and an attacker can learn nothing about the plaintext values by getting masses of right ciphertexts.
This property is known as [IND-CPA security](https://en.wikipedia.org/wiki/Ciphertext_indistinguishability), or "indistinguishability under a chosen-plaintext attack".

There is no way to compare two right ciphertexts with each other.
In order to perform a comparison, a left ciphertext needs to be compared to a right ciphertext.

The typical way to use Cretrit, therefore, is to generate right ciphertexts for storage, and then generate "full" ciphertexts (which have both the left and right part) for querying.
These "querying" ciphertexts are never stored, they're just used for querying, and then discarded.
