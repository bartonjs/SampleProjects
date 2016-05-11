using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using System.Security.Cryptography;
using System.Text;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.UI.Xaml.Media.Animation;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=234238

namespace CryptRunner
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class HmacPage : Page
    {
        public HmacPage()
        {
            this.InitializeComponent();
        }

        private void InputField_TextChanged(object sender, TextChangedEventArgs e)
        {
            byte[] text = Encoding.UTF8.GetBytes(ContentText.Text ?? "");
            byte[] key = Encoding.UTF8.GetBytes(KeyText.Text ?? "");

            //using (HMAC md5 = HMACMD5.Create())
            using (HMAC sha1 = new HMACSHA1(key))
            using (HMAC sha256 = new HMACSHA256(key))
            using (HMAC sha384 = new HMACSHA384(key))
            using (HMAC sha512 = new HMACSHA512(key))
            {
                MD5Output.Text = "Missing in RC1 contract";
                SHA1Output.Text = sha1.ComputeHash(text).ToHexString();
                SHA256Output.Text = sha256.ComputeHash(text).ToHexString();
                SHA384Output.Text = sha384.ComputeHash(text).ToHexString();
                SHA512Output.Text = sha512.ComputeHash(text).ToHexString();
            }
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Frame.GoBack(new DrillInNavigationTransitionInfo());
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);

            InputField_TextChanged(null, null);
        }
    }
}
