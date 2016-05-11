using System.Text;

namespace CryptRunner
{
    internal static class Utils
    {
        public static string ToHexString(this byte[] data)
        {
            StringBuilder builder = new StringBuilder(data.Length * 2);

            foreach (byte b in data)
            {
                builder.Append(b.ToString("X2"));
            }

            return builder.ToString();
        }
    }
}
