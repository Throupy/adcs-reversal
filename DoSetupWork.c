
uint __thiscall CMSCEPSetup::DoSetupWork(CMSCEPSetup *this, ulonglong param_1)
{
    // Resolve the CA config str
    // this + 0x220 is the caFound flag from InitializeDefaults()
    // If no CA was found atomatically (standalone path), use the manually
    // specified config string stoed at this+0x228 instead
    int caFound = *(int *)(this + 0x220)
                      wchar_t *pCAConfigString = NULL;
    if (caFound == 0)
    {
        pCAConfigString = *(wchar_t **)(this + 0x228);
    }

    // PHASE 1 - write NDES config to the registry
    // UpdateCEPRegistry writes all mscep settings to HKLM\SOFTWARE\Microsoft\Crpytography\MSCEP
    // Reads RA name (this+0x198), caType (this+0x500), and CA conf string
    // returns non-zero on success (i guess...?)
    // TODO: Reverse UpdateCEPRegsitry for curiousity
    registryUpdateOk = UpdateCEPRegistry(
        this, *(int *)(this + 0x198), // RA name field
        *(int *)(this + 500),         // ca type (0 standalone, non-zero enterprsie)
        pCAConfigString, );
    if (registryUpdateOk == 0)
    {
        // failed - E_UNEXPECTED
        *(undefined4 *)(this + 0x23c) = 0x737; // internal error code
        hresult = 0x8000ffff;                  // E_UNEXPECTED
        logCode = 0x121a0073;
    }
    else
    {
        // PHASE 2 - create IIS vdirs
        // AddVDir is called twice - once for /certsrv/mscep and once for /certsrv/mscep_admin
        // param3 is the vdir path constant
        // param7 (0, 1) distinguished admin vs client vdir (i think)
        // this calls loads of internal IIS configuration for the NDES apps, not really relevant to this
        // but basically think of this function as 'configure IIS and VDIR for mscep_admin'
        hresult = (uint)AddVDir(
            this,
            *(uint *)(this + 0x1f8), // IIS site ID
            -0x7ff6b608,             // path constant: 'mscep_admin'
            0x1800949e8,             // vdir physical path: 'mscep'
            0x180094a10,             // app pool name: 'SCEP'
            CONCAT44(uVar22, *(undefined4 *)(this + 0x21c)),
            0,                           // 0 = admin vdir
            *(int *)(this + 0x200),      // ?
            *(HRESULT **)(this + 0x208), // ?
            in_stack_ffffffffffffffb0    // ?
        );

        if (FAILED(hresult))
        {
            *(undefined4 *)(this + 0x23c) = 0x738; // internal error code
            logCode = 0x122c0073;                  // TODO: what's this
        }
        else
        {
            hresult = (uint)AddVDir(
                this,
                *(uint *)(this + 0x1f8), // IIS site ID
                -0x7ff6b618,             // path constant: 'mscep'
                0x1800949e8,             // vdir physical path: 'mscep'
                0x180094a10,             // app pool name: 'SCEP'
                CONCAT44(..., *(undefined4 *)(this + 0x21c)),
                1,            // 1 = client vdir
                *(int *)pSid, // TODO where is PSID defined
                *(HRESULT **)(this + 0x208),
                in_stack_ffffffffffffffb0);
            // TODO: end incorrect
            if (FAILED(hresult))
            {
                *(undefined4 *)(this + 0x23c) = 0x738; // internal error code
                logCode = 0x123e0073;                  // TODO: what's this
            }
            else
            {
                // PHASE 3 - resolve service acct SID
                // this+0x21c is the useLocalSystem flag - set during the prev func InitializeDefaults()
                // via put_UseLocalSystem
                // 0 - named svc acct (resolve SID from token)
                // 1 - app pool identity (resolve SID via GetApplicationPoolSid)
                int useLocalSystem = *(int *)(this + 0x21c) if (useLocalSystem == 0)
                {
                    // named service account path
                    // resolve from SID from the impersonation token stored at this 0x210
                    HANDLE hToken = *(HANDLE *)(this + 0x210);
                    if (hToken == NULL)
                    {
                        *(undefined4 *)(this + 0x23c) = 0x739;
                        hresult = 0x80070057; // ERROR_INVALID_PARAMETER — no token handle
                        logCode = 0x124c0073;
                    }
                    else
                    {
                        // first call to GetTokenInformation with NULL buff to get req'd size
                        GetTokenInformation(hToken, TokenUser, NULL, 0, tokenInfoSize);
                        if (tokenInfoSize[0] == 0)
                        {
                            *(undefined4 *)(this + 0x23c) = 0x739;
                            lastError = GetLastError();
                            hresult = myHError(lastError); // conv win32 err code to HRESULT
                            logCode = 0x12540073;
                        }
                        else
                        {
                            // aloc buf and retrieve the token user info
                            pTokenInfoBuffer = LocalAlloc(0x40, tokenInfoSize[0]);
                            if (pTokenInfoBuffer == NULL)
                            {
                                *(undefined4 *)(this + 0x23c) = 0x739;
                                hresult = 0x8007000e; // ERROR_OUTOFMEMORY
                                logCode = 0x125c0073;
                            }
                            else
                            {
                                tokenInfoOk = GetTokenInformation(
                                    hToken, TokenUser,
                                    pTokenInfoBuffer, tokenInfoSize[0], tokenInfoSize);
                                if (tokenInfoOk == 0)
                                {
                                    *(undefined4 *)(this + 0x23c) = 0x739;
                                    lastError = GetLastError();
                                    hresult = myHError(lastError);
                                    logCode = 0x12630073;
                                }
                                // On success falls through to LAB_180023cdd below
                            }
                        }
                    }
                }
                else
                {
                    // app pool identity path
                    // retrieve SID of SCEP app pool account
                    hresult = GetApplicationPoolSid(this, &pAppPoolSid);
                    if (FAILED(hresult))
                    {
                        // Non-fatal, logged but execution continues to LAB_180023cdd.
                        // pResolvedSid will be NULL and SetSecurityOnNamedObject
                        // will be skipped (NULL check below).
                        Ordinal_841(L"SCEP", 0x126b0073); // app pool name - pass to logger
                    }
                }
                // LAB_180023cdd:
                // resolve which sid to use for the registry ACL grant
                // useLocalSystem == 0 means named acct - use token info buffer sid
                // useLocalSystem == 1 means app pool - use pAppPoolSid from GetApplicationPoolSid
                pResolvedSid = pAppPoolSid;
                if (useLocalSystem == 0)
                {
                    pResolvedSid = *(LPWSTR *)pTokenInfoBuffer;
                }

                // PHASE 4 - grant service acct SID read/write access to MSCEP reg key
                // if pResolvedSid is NULL, this is skipped entirely
                // SetSecurityOnNamedObject retcode is -1 (DWORD) on failure
                if ((pResolvedSid == NULL) ||
                    (lastError = SetSecurityOnNamedObject(
                         L"MACHINE\\Software\\Microsoft\\Cryptography\\MSCEP",
                         SE_REGISTRY_KEY,
                         pTokenInfoBuffer, // TOKEN_USER struct
                         pResolvedSid      // SID to grant access to
                         ),
                     -1 < (int)lastError))
                {
                    // PHASE 5 - configure IIS req filtering
                    // SetIISFilteringLimits is called twice, supose this is once for each vdir
                    // both calls are non fatal, errors are logged but do not abort installation
                    // sets allowDoubleEscaping=true and maxQueryString=0x10000 (65536). lines up with observed behaviour
                    hresult = SetIISFilteringLimits(0x1800952f0); // mscep
                    if (hresult != 0)
                    {
                        Ordinal_839(0x12860073, hresult); // logged, not fatal
                    }
                    hresult = SetIISFilteringLimits(0x1800952d8); // mscep_admin
                    if (hresult != 0)
                    {
                        Ordinal_839(0x12890073, hresult); // logged, not fatal
                    }

                    // this+500 is the caType flag — 0=Standalone, non-zero=Enterprise.
                    int caType = *(int *)(this + 500);

                    if (caType != 0)
                    {
                        // PHASE 6 (Enterprise CA path) - publish RA cert templates
                        // DoCertSrvEnterpriseChanges publishes EnrollmentAgentOffline, CEPEncryption,
                        // and IPSECIntermediateOffline templates to the CA via CERTCA.dll (RPC/DCOM)
                        // then sets template ACLs
                        // requires 'manage CA permissions' on the target CA
                        // on success: goto LAB_180023ddb
                        // on failure: set error, fall to LAB_180024068
                        pResolvedSidForEnterprise = NULL;
                        if (useLocalSystem == 0)
                        {
                            pResolvedSidForEnterprise = *(wchar_t **)pTokenInfoBuffer;
                        }

                        hresult = DoCertSrvEnterpriseChanges(
                            this,
                            pResolvedSidForEnterprise,
                            pTokenInfoBuffer // account name
                        );
                        if (FAILED(hresult))
                        {
                            *(undefined4 *)(this + 0x23c) = 0x73a;
                            logCode = 0x12940073;
                        }
                        else
                        {
                            hresult = CertSrvStartStopService(this, 0, iVar2); // 0 = stop
                            if (hresult == 0)
                            {
                                hresult = CertSrvStartStopService(this, 1, iVar2); // 1 = start
                                if (hresult == 0)
                                {
                                    // CertSvc restarted successfully.
                                    // Fall through to Standalone path (LAB_180023ddb)
                                    // to continue with RA name building and certificate enrollment.
                                    goto LAB_180023ddb;
                                }
                                logCode = 0x129c0073;
                            }
                            else
                            {
                                logCode = 0x12990073;
                            }
                        }
                    }
                    // LAB_180023ddb - Standalone CA path entry point.
                    // Enterprise CA also arrives here after DoCertSrvEnterpriseChanges + CertSvc restart.
                    // PHASE 7 - build RA subject name
                    // alloc buffer and iterate over the seven RA identity fields
                    // stored at this+0x1a0 through this+0x1c8 (name, email, company, etc etc)
                    // concat non-empty fields separated by '/' separators using g_rgRAEnrollInfo as the field prefix (creative!)
                    raSubjectName = LocalAlloc(LMEM_FIXED, 2);
                    if (raSubjectName == NULL)
                    {
                        *(undefined4 *)(this + 0x23c) = 0x73b;
                        hresult = 0x8007000e; // ERROR_OUTOFMEMORY
                        logCode = 0x12a70073;
                    }
                    else
                    {
                        *raSubjectName = L'\0';
                        // Iterate over the seven RA identity fields, growing the buffer
                        // via LocalReAlloc as each non-empty field is appended.
                        // g_rgRAEnrollInfo provides the OID prefix for each field
                        int fieldIndex = 0;
                        do
                        {
                            // string concatenation loop - building raSubjectName
                            //  from RA identity fields
                            // ommitted for brevity (TODO: is it?)
                            fieldIndex++;
                        } while (fieldIndex < 7);
                        // Resolve CSP provider names from the object.
                        // this+0x1d8 is the CSP info array base pointer.
                        // this+0x1ec is the encryption key CSP index.
                        // this+0x1e4 is the signing key CSP index.
                        // Each entry is 0x50 bytes — provider name is first field.
                        pEncryptionProviderName = *(OLECHAR **)(*(longlong *)(this + 0x1d8) +
                                                                (ulonglong) * (uint *)(this + 0x1ec) * 0x50);
                        pSigningProviderName = *(OLECHAR **)(*(longlong *)(this + 0x1d8) +
                                                             (ulonglong) * (uint *)(this + 0x1e4) * 0x50);

                        // PHASE 8 - Enroll RA certs
                        // EnrollForRACert is called twice:
                        //  First cert - EnrollmentAgentOffline
                        //  Second - CEPEncryption
                        // Uses IcertRequest::Submit() to the target CA
                        // dispo 3 - issued, 5 - pending
                        // error 0x80070005 here indicates CA DACL issue, though likely would have already hit tbh
                        hresult = EnrollForRACert(
                            this,
                            raSubjectName,
                            pSigningProviderName,
                            *(OLECHAR *)(this + 0x1e8), // signing key length
                            2,                          // keySpec = signature
                            -0x7ff6b1b8,                // EnrollmentAgentOffline template constant
                            pResolvedSid,
                            pSid);
                        if (hresult == S_OK)
                        {
                            hresult = EnrollForRACert(
                                this,
                                raSubjectName,
                                pEncryptionProviderName,
                                *(OLECHAR *)(this + 0x1f0), // encryption key length
                                1,                          // keySpec = exchange
                                -0x7ff6b188,                // CEPEncryption template constant
                                pResolvedSid,
                                pSid);
                            if (FAILED(hresult))
                            {
                                Ordinal_839(0xf410073);
                                goto LAB_180024001;
                            }
                        }
                        else
                        {
                            Ordinal_839(0xf380073);
                        }
                        // LAB_180024001:
                        if (FAILED(hresult))
                        {
                            *(undefined4 *)(this + 0x23c) = 0x73c;
                            logCode = 0x12d30073;
                            goto LAB_180024068; // bail out
                        }
                        // PHASE 9 - write CA config changes
                        // DoCertSrvRegChanges calls ICertAdmin2::SetCAProperty() with PROPID_CA_SUBJECTTEMPLATE (0x11)
                        // to configure teh CA to include the req'd OIDs in issued cert subjects
                        // does the whole certutil -setreg CA\SubjectTemplate +UnstructuredName business, same for DeviceSerialNumber and UnstructuredAddress
                        hresult = (uint)DoCertSrvRegChanges(this, raSubjectName);
                        if (FAILED(hresult))
                        {
                            *(undefined4 *)(this + 0x23c) = 0x73d;
                            logCode = 0x12dc0073;
                        }
                        else
                        {
                            // PHASE 10 - restart certsvc to apply config changes (deep down they are reg)
                            // stop then strat CA via RPC
                            // requires Manage CA, or loc admin on the CA.
                            hresult = CertSrvStartStopService(this, 0, iVar2); // 0 = stop
                            if (hresult == 0)
                            {
                                hresult = CertSrvStartStopService(this, 1, iVar2); // 1 = start
                                if (hresult == 0)
                                {
                                    goto LAB_180024074; // success
                                }
                                logCode = 0x12e40073;
                            }
                            else
                            {
                                logCode = 0x12e10073;
                            }
                        }
                    }
                }
                else
                {
                    // SetSecurityOnNamedObject failed
                    *(undefined4 *)(this + 0x23c) = 0x737;
                    hresult = 0x8000ffff; // E_UNEXPECTED
                    logCode = 0x127d0073;
                }
            }
        }
    }
    // LAB_180024068:
    LOG_ERROR_INTERNAL(logCode, hresult);

    // LAB_180024074:
    // Cleanup
    if (pAppPoolSid != NULL)
    {
        LocalFree(pAppPoolSid);
    }
    if (pTokenInfoBuffer != NULL)
    {
        LocalFree(pTokenInfoBuffer);
    }
    if (raSubjectName != NULL)
    {
        LocalFree(raSubjectName);
    }
    SysFreeString(NULL);

    return hresult;
}