#include <iostream>
#include <atlbase.h>
#include <atlstr.h>
#include <comdef.h>

using namespace std;

bool GetAttribute(LPWSTR name, BSTR* pstrValue)
{
    return true;
}

void FillMyString(BSTR* ptrbstrVal)
{
    CComBSTR bstrVal(L"Test");
    bstrVal.CopyTo(ptrbstrVal);
}
// Function that accepts CComBSTR
void DisplayBSTR(const wchar_t* text)
{
    BSTR myBSTR = SysAllocString(L"Hello");

    FillMyString(&myBSTR);

    CComBSTR testBSTR;

    for (int i = 0; i < 5; i++)
    {
        GetAttribute(L"Test", &testBSTR);
    }

}

int main()
{
    // Initialize COM
    HRESULT hr = CoInitialize(NULL);

    if (FAILED(hr))
    {
        cout << "COM initialization failed" << endl;
        return -1;
    }

    // Create a CComBSTR
    CComBSTR message(L"Hello from COM using CComBSTR!");

    // Call function
    DisplayBSTR(message);

    // Cleanup COM
    CoUninitialize();

    return 0;
}
