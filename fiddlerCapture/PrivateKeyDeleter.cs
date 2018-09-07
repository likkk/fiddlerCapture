using System;
using System.Collections.Generic;
using System.Security.Cryptography;

using Fiddler;

namespace FiddlerCore
{
    public class PrivateKeyDeleter
    {
        private readonly IDictionary<Type, Action<AsymmetricAlgorithm>> privateKeyDeleters =
            new Dictionary<Type, Action<AsymmetricAlgorithm>>();

        public PrivateKeyDeleter()
        {
            this.AddPrivateKeyDeleter<RSACng>(this.DefaultRSACngPrivateKeyDeleter);
            this.AddPrivateKeyDeleter<RSACryptoServiceProvider>(this.DefaultRSACryptoServiceProviderPrivateKeyDeleter);
        }

        public void AddPrivateKeyDeleter<T>(Action<T> keyDeleter) where T : AsymmetricAlgorithm
        {
            this.privateKeyDeleters[typeof(T)] = (a) => keyDeleter((T)a);
        }

        public void DeletePrivateKey(AsymmetricAlgorithm a)
        {
            for (Type t = a.GetType(); t != null; t = t.BaseType)
            {
                Action<AsymmetricAlgorithm> deleter;
                if (this.privateKeyDeleters.TryGetValue(t, out deleter))
                {
                    deleter(a);
                    return;
                }
            }

            FiddlerApplication.Log.LogString("No private key deleter found for " + a.GetType());
        }

        private void DefaultRSACryptoServiceProviderPrivateKeyDeleter(RSACryptoServiceProvider rsaCryptoServiceProvider)
        {
            rsaCryptoServiceProvider.PersistKeyInCsp = false;
            rsaCryptoServiceProvider.Clear();
        }

        private void DefaultRSACngPrivateKeyDeleter(RSACng rsaCng)
        {
            rsaCng.Key.Delete();
            rsaCng.Clear();
        }
    }
}
