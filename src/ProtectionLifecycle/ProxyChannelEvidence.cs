using System.ComponentModel;
using System.Diagnostics;
using System.Formats.Asn1;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.Win32.SafeHandles;
using ClaudeCodeProtection.Security;

namespace ProtectionLifecycle;

internal sealed record TlsValidationObservation(int PolicyErrors,int[] ChainStatus,bool CertificatePresent,bool ChainPresent);
internal sealed record TlsCertificateObservation(string SHA256,int[] ChainStatus,string[] CrlDistributionPoints,string? ExtensionFailure);
