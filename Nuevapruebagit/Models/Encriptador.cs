using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

using System.IO;
using System.Security.Cryptography;
using System.Configuration;
using System.Text;

namespace Nuevapruebagit.Models
{
    public class Encriptador
    {
        private string texto;
        private string clave;

        public Encriptador(string texto)
        {
            this.texto = texto;
            this.Clave = ConfigurationManager.AppSettings["claveAES"];
        }

        public Encriptador()
        {
            this.texto = "";
            this.Clave = ConfigurationManager.AppSettings["claveAES"];
        }

        public string Texto { get => texto; set => texto = value; }
        private string Clave { get => clave; set => clave = value; }

        // Método para encriptar un texto con AES
        public string Encriptar(string textoPlano)
        {
            byte[] textoPlanoBytes = Encoding.UTF8.GetBytes(textoPlano);//pasa el texto a bytes
            using (Aes aesAlg = Aes.Create())//instancia metodo AES
            {
                aesAlg.Key = ObtenerClave(Clave, aesAlg.KeySize / 8);//Instancia la clave de cifrado y 'ObtenerClave' devuelve la calve en bytes
                aesAlg.IV = aesAlg.IV; // Vector de inicialización generado automáticamente

                using (var encriptador = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV))//crea un objeto encriptador
                using (var msEncriptado = new MemoryStream())//es un flujo de memoria donde se guarda el texto cifrado
                {
                    msEncriptado.Write(aesAlg.IV, 0, aesAlg.IV.Length); // Guardar IV(Vector de inicializacion) al inicio
                    using (var csEncriptado = new CryptoStream(msEncriptado, encriptador, CryptoStreamMode.Write)) //conecta el cifrado con MemoryStream
                    {
                        csEncriptado.Write(textoPlanoBytes, 0, textoPlanoBytes.Length);//Encripta el texto en bytes
                        csEncriptado.FlushFinalBlock();//Verifica que se haya cifrado correctamente
                    }
                    return Convert.ToBase64String(msEncriptado.ToArray());//retorna el texto en String
                }
            }
        }
        // Método para desencriptar el texto encriptado
        public string Desencriptar(string textoCifrado)
        {
            byte[] textoCifradoBytes = Convert.FromBase64String(textoCifrado);//pasa el texto a bytes
            using (Aes aesAlg = Aes.Create())
            {
                byte[] iv = new byte[aesAlg.BlockSize / 8];//Obtiene el tamaño de IV
                Array.Copy(textoCifradoBytes, iv, iv.Length); // Extraer el IV del inicio del texto encriptado

                aesAlg.Key = ObtenerClave(Clave, aesAlg.KeySize / 8);//Asigna la clave extraido
                aesAlg.IV = iv;//Asigna el IV extraido

                using (var desencriptador = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV))//Crea un objeto desencriptador
                using (var msDesencriptado = new MemoryStream(textoCifradoBytes, iv.Length, textoCifradoBytes.Length - iv.Length))//lee el texto cifrado, quitando el IV
                using (var csDesencriptado = new CryptoStream(msDesencriptado, desencriptador, CryptoStreamMode.Read))//conecta el flujo de desencripción al MemoryStrem
                using (var srDesencriptado = new StreamReader(csDesencriptado))//lee el texto desencriptado y lo devuelve como String
                {
                    return srDesencriptado.ReadToEnd();
                }
            }
        }
        // Método para generar una clave a partir de la contraseña usando SHA-256 y garantiza que tenag el tamaño necesarioen 256 bits
        private byte[] ObtenerClave(string clave, int tamaño)
        {
            using (SHA256 sha256 = SHA256.Create())
            {
                byte[] claveBytes = Encoding.UTF8.GetBytes(Clave);//pasa el texto a bytes
                byte[] hash = sha256.ComputeHash(claveBytes);//calcula el valor para la matriz de bytes
                Array.Resize(ref hash, tamaño);//readecua la matriz al tamaño necesario
                return hash;
            }
        }
    }
}