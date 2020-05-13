'https://www.motobit.com/tips/detpg_BinASP/
Set fso = CreateObject ("Scripting.FileSystemObject")
Set stdout = fso.GetStandardStream (1)
Set RE = New RegExp
RE.IgnoreCase = False
RE.Global     = True

Function ReadFile(fname)
	Dim inStream: Set inStream = WScript.CreateObject("ADODB.Stream") ' ADODB stream object used
	inStream.Open 'open with no arguments makes the stream an empty container 
	inStream.type=1
	inStream.LoadFromFile(fname)
	ReadFile=inStream.Read
	inStream.Close
End Function

call StrComp("","")
RE.Pattern = ReadFile("test.txt")
' force compile
call RE.replace("aaa", "bb")
InputBox("pause")







