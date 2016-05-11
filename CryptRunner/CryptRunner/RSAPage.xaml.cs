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
    public sealed partial class RSAPPage : Page
    {
        private RSA _rsa;
        private bool _isEphemeral;

        public RSAPPage()
        {
            this.InitializeComponent();
        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            Frame.GoBack(new DrillInNavigationTransitionInfo());
        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            base.OnNavigatedTo(e);
            UpdateRsaValues();
        }

        protected override void OnNavigatingFrom(NavigatingCancelEventArgs e)
        {
            base.OnNavigatingFrom(e);

            if (_rsa != null)
            {
                _rsa.Dispose();
                _rsa = null;
            }
        }

        private void Generate_Click(object sender, RoutedEventArgs e)
        {
            int selectedValue = Convert.ToInt32(((ComboBoxItem)(KeySizeSelector.SelectedValue)).Content);

            if (_rsa != null && (_rsa.KeySize == selectedValue || !_isEphemeral))
            {
                _rsa.Dispose();
                _rsa = null;
            }

            if (_rsa == null)
            {
                _rsa = new RSACng();
            }

            _isEphemeral = true;
            _rsa.KeySize = selectedValue;
            UpdateRsaValues();
        }

        private void UpdateRsaValues()
        {
            if (_rsa == null)
            {
                ModulusValue.Text = ExponentValue.Text = DValue.Text = PValue.Text = QValue.Text = "--";
                return;
            }

            RSAParameters rsaParams;

            try
            {
                rsaParams = _rsa.ExportParameters(true);
            }
            catch (CryptographicException)
            {
                rsaParams = _rsa.ExportParameters(false);
            }

            ModulusValue.Text = rsaParams.Modulus.ToHexString();
            ExponentValue.Text = rsaParams.Exponent.ToHexString();

            if (rsaParams.D != null)
            {
                DValue.Text = rsaParams.D.ToHexString();
                PValue.Text = rsaParams.P.ToHexString();
                QValue.Text = rsaParams.Q.ToHexString();
            }
            else
            {
                DValue.Text = PValue.Text = QValue.Text = "--";
            }
        }

        private void Load_Click(object sender, RoutedEventArgs e)
        {
            if (_rsa != null)
            {
                _rsa.Dispose();
                _rsa = null;
            }

            _isEphemeral = false;

            try
            {
                CngKey cngKey = CngKey.Open(((ComboBoxItem)KeyNameSelector.SelectedItem).Content.ToString());
                _rsa = new RSACng(cngKey);
                UpdateRsaValues();
            }
            catch (CryptographicException ex)
            {
                UpdateRsaValues();
                ModulusValue.Text = ex.Message;
            }
        }

        private void Create_Click(object sender, RoutedEventArgs e)
        {
            if (_rsa != null)
            {
                _rsa.Dispose();
                _rsa = null;
            }

            _isEphemeral = false;

            int selectedValue = Convert.ToInt32(((ComboBoxItem)(KeySizeSelector.SelectedValue)).Content);

            try
            {
                var cngParameters = new CngKeyCreationParameters
                {
                    ExportPolicy = CreateExportable.IsOn ? CngExportPolicies.AllowPlaintextExport : CngExportPolicies.None,
                    KeyCreationOptions = CngKeyCreationOptions.None,
                    KeyUsage = CngKeyUsages.Decryption | CngKeyUsages.Signing,
                    Provider = CngProvider.MicrosoftSoftwareKeyStorageProvider,
                    Parameters =
                    {
                        new CngProperty("Length", BitConverter.GetBytes(selectedValue), CngPropertyOptions.None),
                    },
                };

                CngKey cngKey = CngKey.Create(
                    CngAlgorithm.Rsa,
                    ((ComboBoxItem)KeyNameSelector.SelectedItem).Content.ToString(),
                    cngParameters);

                _rsa = new RSACng(cngKey);
                UpdateRsaValues();
            }
            catch (CryptographicException ex)
            {
                UpdateRsaValues();
                ModulusValue.Text = ex.Message;
            }
        }

        private void Delete_Click(object sender, RoutedEventArgs e)
        {
            if (_rsa != null)
            {
                _rsa.Dispose();
                _rsa = null;
            }

            try
            {
                CngKey cngKey = CngKey.Open(((ComboBoxItem)KeyNameSelector.SelectedItem).Content.ToString());
                cngKey.Delete();
                UpdateRsaValues();
            }
            catch (CryptographicException ex)
            {
                UpdateRsaValues();
                ModulusValue.Text = ex.Message;
            }
        }
    }
}
