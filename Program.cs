using System.Net.Security;
using System.Security.Cryptography;
using System.Text;

class ISPW2 {
	static void Main() {
		Console.Write("Enter secret key (16, 24, or 32 characters): ");
		string key = Console.ReadLine();
		Console.Clear();

		CipherMode mode;
		while (true) {
			Console.WriteLine("Choose mode of operation:");
			Console.WriteLine("1. ECB");
			Console.WriteLine("2. CBC");
			Console.WriteLine("3. CFB");
			string choice = Console.ReadLine();

			if (choice == "1") {
				mode = CipherMode.ECB;
				break;
			}
			else if (choice == "2") {
				mode = CipherMode.CBC;
				break;
			}
			else if (choice == "3") {
				mode = CipherMode.CFB;
				break;
			}
			else {
				Console.WriteLine("Invalid option. Please try again.");
			}

			Console.Clear();
		}
		
		while (true) {
			Console.WriteLine("1. Encrypt plaintext");
			Console.WriteLine("2. Decrypt from file");
			Console.WriteLine("3. Exit");
			string choice = Console.ReadLine();
			Console.Clear();

			if (choice == "1") {
				Console.Write("Enter plaintext: ");
				string text = Console.ReadLine();
				string encryptedText = Encryption(text, key, mode);
				Console.WriteLine("Encrypted text: " + encryptedText);
				File.WriteAllText("encrypted.txt", encryptedText);
			}
			else if (choice == "2") {
				string text = File.ReadAllText("encrypted.txt");
				string decryptedText = Decryption(text, key, mode);
				Console.WriteLine("Decrypted text: " + decryptedText);
			}
			else if (choice == "3") {
				break;
			}
			else {
				Console.WriteLine("Invalid option. Please try again.");
			}
		}
	}

	public static string Encryption(string text, string key, CipherMode mode) {
		using (Aes aes = Aes.Create()) {
			aes.Key = Encoding.UTF8.GetBytes(key);
			aes.Mode = mode;
			if (mode != CipherMode.ECB) {
				aes.GenerateIV();
			}

			ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

			using (MemoryStream memoryStream = new MemoryStream()) {
				if (mode != CipherMode.ECB) {
					memoryStream.Write(aes.IV, 0, aes.IV.Length);
				}

				using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write)) {
					using (StreamWriter streamWriter = new StreamWriter(cryptoStream)) {
						streamWriter.Write(text);
					}
				}

				return Convert.ToBase64String(memoryStream.ToArray());
			}
		}
	}

	public static string Decryption(string encryptedText, string key, CipherMode mode) {
		byte[] encryptedBytes = Convert.FromBase64String(encryptedText);

		using (Aes aes = Aes.Create()) {
			aes.Key = Encoding.UTF8.GetBytes(key);
			aes.Mode = mode;

			using (MemoryStream memoryStream = new MemoryStream(encryptedBytes)) {
				if (mode != CipherMode.ECB) {
					byte[] iv = new byte[aes.BlockSize / 8];
					memoryStream.Read(iv, 0, iv.Length);
					aes.IV = iv;
				}

				ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

				using (CryptoStream cryptopStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read)) {
					using (StreamReader streamReader = new StreamReader(cryptopStream)) {
						return streamReader.ReadToEnd();
					}
				}
			}
		}
	}
}