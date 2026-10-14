# Dark Matter — RSA Private Key Recovery

**Difficulty:** Easy  
**Topic:** Cryptography (RSA)  
**Tools:** Linux Terminal, [FactorDB](https://factordb.com/), Calculator

## Summary

This room focuses on recovering an RSA private exponent to help restore files encrypted by ransomware. By examining a public key left in the `/tmp` directory, I identified the RSA parameters, factored the modulus into its prime factors, and used the RSA key-generation equations to calculate the private exponent. The challenge illustrates why RSA depends on strong key generation and why exposed debugging artifacts should be investigated during incident response.

## Scenario

Hackfinity High School has been targeted by DarkInjector ransomware, which encrypted several critical files. Working with Void, the objective is to recover the RSA private key needed for decryption. The challenge hints that the ransomware developers left debugging information in the `/tmp` directory.

## Question

**Can you find the RSA private key?**

## Solution

### Step 1: Locate the public key

Because the scenario mentioned debugging information in `/tmp`, I started by listing the contents of that directory:

```bash
cd /tmp
ls -la
```

I found a file named `public_key.txt` and displayed its contents:

```bash
cat public_key.txt
```

The file contained two RSA public-key parameters:

- **`n` (modulus):** The product of two prime numbers, `p` and `q`.
- **`e` (public exponent):** Used with `n` for RSA encryption or signature verification, depending on the application.

For this challenge, the goal was to recover the corresponding **private exponent, `d`**.

### Step 2: Factor the modulus

RSA begins with two prime numbers, `p` and `q`, whose product is the modulus:

$$
n = p \times q
$$

I entered the value of `n` into [FactorDB](https://factordb.com/) to look for its prime factors. The challenge's modulus was factorable, allowing me to identify `p` and `q`.

In a properly generated modern RSA key, factoring a sufficiently large modulus is not practical with this approach.

### Step 3: Calculate Euler's totient

Once I had the distinct prime factors `p` and `q`, I calculated Euler's totient:

$$
\varphi(n) = (p - 1)(q - 1)
$$

Equivalently:

$$
\varphi(n) = n - p - q + 1
$$

### Step 4: Recover the private exponent

The private exponent `d` is the modular multiplicative inverse of `e` modulo `\varphi(n)`:

$$
d \equiv e^{-1} \pmod{\varphi(n)}
$$

This means `d` satisfies:

$$
(ed) \bmod \varphi(n) = 1
$$

**Important:** This is a modular inverse calculation, **not** regular division of `\varphi(n)` by `e`.

I substituted the challenge's values into the equation to calculate `d`. Python can perform the same calculation:

```python
# Replace these placeholders with values from the challenge.
p = ...
q = ...
e = ...

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)

print(f"Private exponent (d): {d}")
```

The recovered private exponent was the value required to answer the room's question. Together with the modulus and other parameters as needed, it can be used to reconstruct an RSA private key.

## Lessons Learned

- **Understand the relationship between RSA public and private keys.** The public parameters `(n, e)` do not normally reveal the private exponent, but knowing the prime factors of `n` makes it possible to calculate `\varphi(n)` and recover `d`.
- **Modular arithmetic is essential to RSA.** Finding `d` requires a modular multiplicative inverse, not ordinary division. Using the correct operation prevents a common mistake when solving RSA challenges.
- **Key strength matters.** RSA is only secure when its modulus is generated using appropriately sized, unpredictable primes and a trustworthy key-generation process. A modulus that can be factored easily makes the private key recoverable.
- **Investigate temporary files and debugging artifacts.** Files in locations such as `/tmp` may contain valuable clues during malware analysis. Developers should also avoid leaving sensitive diagnostic material behind in production systems.
- **Distinguish a challenge weakness from a real-world recovery method.** This room deliberately provides a factorable modulus. Strongly generated RSA keys generally cannot be recovered by simply submitting `n` to an online factoring service.


