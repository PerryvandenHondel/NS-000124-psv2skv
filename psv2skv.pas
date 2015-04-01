{ =====================================================================================================================

	PROGRAM:
		psv2skv.exe

	DESCRIPTION:
		Convert a PSV (Pipe Separated Values) output text file to an Splunk Key-Value text file to be indexed
  
	VERSION:
		07	2015-03-31	PVDH	Modifications:
								1)	Write a log file with file processed and statistics
								2)	Add the parameter options for debug and help:
									--debug, -d: debug on
									--help, -h ,-?: Show usage.
		06	2015-03-20	PVDH	Modifications:
								1) Clean-up code.
		05	2015-03-16	PVDH	Modifications:
								1) Renamed the standard event_id key to eid
								2) Use an event definition (.evtd) per event to process. Eliminate the TRUE option per event.
		04	2015-03-11	PVDH	Modifications:
								1) Do not process computer accounts in account field to reduce log size.
								   Changed in function ConvertFile()
		03	2015-03-10	PVDH	Modifications
		02	2015-03-03	PVDH	Modifications
		01	2014-10-29	PVDH	Initial version

	RETURNS:
		RESULT_OK			0   OK, see 'output.skv'
		RESULT_ERR_CONV		1   No conversion done
		RESULT_ERR_INPUT	2   Input PSV file not found
		RESULT_ERR_CONF_E	3	Error in config file Event
		RESULT_ERR_CONF_ED	4	Error in config file EventDetail
		
	FUNCTIONS AND PROCEDURES:
		function ConvertFile
		function GetEventType
		function GetKeyName
		function GetKeyType
		function ProcessThisEvent
		procedure WriteDebug
		procedure EventDetailReadConfig
		procedure EventDetailRecordAdd
		procedure EventDetailRecordShow
		procedure EventFoundAdd
		procedure EventFoundStats
		procedure EventIncreaseCount
		procedure EventReadConfig
		procedure EventRecordAdd
		procedure EventRecordShow
		procedure ProcessEvent
		procedure ProcessLine
		procedure ProgramDone
		procedure ProgramInit
		procedure ProgramRun
		procedure ProgramTest
		procedure ProgramTitle
		procedure ProgramUsage
		procedure ShowStatistics
		
	
 =====================================================================================================================} 


program psv2skv;


{$mode objfpc}
{$H+}


uses
	Classes, 
	StrUtils,
	Sysutils,
	UTextFile,
	USplunkFile,
	USupportLibrary;
	
	
const
	ID 					=	'000124';
	VERSION 			=	'07';
	DESCRIPTION 		=	'Convert PSV (Pipe Separated Values) Event Log to SKV (Splunk Key-Values) format, based on event definition files (.evd)';
	RESULT_OK			=	0;
	RESULT_ERR_CONV		=	1;
	RESULT_ERR_INPUT	=	2;
	RESULT_ERR_CONF_E	=	3;
	RESULT_ERR_CONF_ED	=	4;
	SEPARATOR_PSV		=	'|';	
	SEPARATOR_CSV		=	';';
	STEP_MOD			=	137;		// Step modulator for echo mod, use a off-number, not rounded as 10, 15 etc. to see the changes.
	
	
type
	// Type definition of the Event Records
	TEventRecord = record
		eventId: integer;
		description: string;
		count: integer;
		osVersion: word;
	end;
	TEventArray = array of TEventRecord;

	TEventDetailRecord = record
		eventId: integer;           // Event number
		keyName: string;            // Key name under Splunk
		position: word;       	   	// Position in the Logparser string
		isString: boolean;          // Save value as string (True=String, False=number)
	end;
		
    TEventDetailArray = array of TEventDetailRecord;
	
	TEventFoundRecord = record
		eventId: integer;
		count: integer;
	end;
	TEventFoundArray = array of TEventFoundRecord;

	
var
	pathInput: string;
	programResult: integer;
	EventDetailArray: TEventDetailArray;
	EventArray: TEventArray;
	EventFound: TEventFoundArray;
	tfPsv: CTextFile;
	tfSkv: CTextFile;
	tfLog: CTextFile;
	blnDebug: boolean;
	

	
function ProcessThisEvent(e: integer): boolean;
{
	Read the events from the EventArray.
	Return the status for isActive.
	
	Returns
		TRUE		Process this event.
		FALSE		Do not process this event.
}
var
	i: integer;
	r: boolean;
begin
	r := false;
	
	//WriteLn;
	//WriteLn('ProcessThisEvent(): e=', e);
	for i := 0 to High(EventArray) do
	begin
		//WriteLn(i, chr(9), EventArray[i].eventId, Chr(9), EventArray[i].isActive);
		if EventArray[i].eventId = e then
		begin
			r := true;
			break;
			//WriteLn('FOUND ', e, ' ON POS ', i);
			// Found the event e in the array, return the isActive state
			//r := EventArray[i].isActive;
			//break;
		end;
	end;
	//WriteLn('ShouldEventBeProcessed():', Chr(9), e, Chr(9), r);
	ProcessThisEvent := r;
end;
	

function GetKeyName(eventId: integer; position: integer): string;
{
	Returns the KeyName of a valid position
}
var
	i: integer;
	r: string;
begin
	r := '';
	//WriteLn('GetKeyName(', eventId, ',', position, ')');
	
	for i := 0 to High(EventDetailArray) do
	begin
		if (eventId = EventDetailArray[i].eventId) then
		begin
			//WriteLn(Chr(9), IntToStr(EventDetailArray[i].position));
			if position = EventDetailArray[i].position then
			begin
				r := EventDetailArray[i].keyName;
				//if EventDetailArray[i].isActive = true then
				//begin
					//WriteLn('FOUND FOR EVENTID ', eventId, ' AND ACTIVE KEYNAME ON POSITION ', position);
				//end;
			end;
		end;
	end;
	GetKeyName := r;
end; // of function GetKeyName



function GetEventType(eventType: integer): string;
{
	Returns the Event Type string for a EventType

	1		ERROR
	2		WARNING
	3		INFO
	4		SUCCESS	AUDIT
	5		FAILURE AUDIT
	
	Source: https://msdn.microsoft.com/en-us/library/aa394226%28v=vs.85%29.aspx
}	
var
	r: string;
begin
	r := '';
	
	case eventType of
		1: r := 'ERR';	// Error
		2: r := 'WRN';	// Warning
		3: r := 'INF';	// Information
		4: r := 'AUS';	// Audit Success
		5: r := 'AUF';	// Audit Failure
	else
		r := 'UKN';		// Unknown Note: should never be seen.
	end;
	GetEventType := r;
end; // of function GetEventType



function GetKeyType(eventId: integer; position: integer): boolean;
{
	Returns the KeyType of a valid position
}
var
	i: integer;
	r: boolean;
begin
	r := false;
	//WriteLn('GetKeyName(', eventId, ',', position, ')');
	
	for i := 0 to High(EventDetailArray) do
	begin
		if (eventId = EventDetailArray[i].eventId) then
		begin
			//WriteLn(Chr(9), IntToStr(EventDetailArray[i].position));
			if position = EventDetailArray[i].position then
				r := EventDetailArray[i].isString;
			//begin
				//if EventDetailArray[i].isActive = true then
				//begin
					//WriteLn('FOUND FOR EVENTID ', eventId, ' AND ACTIVE KEYNAME ON POSITION ', position);
				//end;
			//end;
		end;
	end;
	GetKeyType := r;
end; // of function GetKeyType	
	

	
procedure WriteDebug(t: string);
begin
	if blnDebug = true then
		WriteLn('DEBUG: ' + t);
end; // of procedure WriteDebug

	
	
procedure EventFoundAdd(newEventId: integer);
var
	size: integer;
begin
	size := Length(EventFound);
	SetLength(EventFound, size + 1);
	EventFound[size].eventId := newEventId;
	EventFound[size].count := 1;
end; // of procedure EventFoundAdd


	
procedure EventIncreaseCount(SearchEventId: word);
var
	newCount: integer;
	i: integer;
begin
	for i := 0 to High(EventArray) do
	begin
		if EventArray[i].eventId = SearchEventId then
		begin
			newCount := EventArray[i].count + 1;
			EventArray[i].count := newCount
		end; // of procedure EventIncreaseCount
	end;
end; // of procedure EventIncreaseCount



procedure EventFoundStats();
var
	i: integer;
begin
	WriteLn;
	WriteLn('Found Events Stats:');
	WriteLn;
	WriteLn('Event', Chr(9), 'Count');
	WriteLn('-----', Chr(9), '------');
	for i := 0 to High(EventFound) do
	begin
		//WriteLn('record: ' + IntToStr(i));
		Writeln(EventFound[i].eventId:5, Chr(9), EventFound[i].count:6);
	end;
	WriteLn;
end;

	
procedure ShowStatistics();
var
	i: integer;
	totalEvents: longint;
begin
	totalEvents := 0;
	
	WriteLn();
	
	WriteLn('STATISTICS:');
	tfLog.WriteToFile('STATISTICS:');
	
	WriteLn();
	tfLog.WriteToFile('');
	
	WriteLn('Evt', Chr(9), 'Number', Chr(9), 'Description');
	tfLog.WriteToFile('Evt' + Chr(9) + 'Number' + Chr(9) + 'Description');
	
	WriteLn('----', Chr(9), '------', Chr(9), '--------------------------------------');
	tfLog.WriteToFile('----' + Chr(9) + '------' + Chr(9) + '--------------------------------------');
	
	for i := 0 to High(EventArray) do
	begin
		//WriteLn('record: ' + IntToStr(i));
		Writeln(EventArray[i].eventId:4, Chr(9), EventArray[i].count:6, Chr(9), EventArray[i].description, ' (', EventArray[i].osVersion, ')');
		tfLog.WriteToFile(IntToStr(EventArray[i].eventId) + Chr(9) + IntToStr(EventArray[i].count) + Chr(9) + EventArray[i].description + ' (' + IntToStr(EventArray[i].osVersion) + ')');
		
		totalEvents := totalEvents + EventArray[i].count;
	end;
	WriteLn;
	tfLog.WriteToFile('');
	
	WriteLn('Total of events ', totalEvents, ' converted.');
	tfLog.WriteToFile('Total of events ' +  IntToStr(totalEvents) + ' converted.');
	
	WriteLn;
end; // of procedure ShowStatistics
	

	
procedure ProcessEvent(eventId: integer; la: TStringArray);
var
	x: integer;
	strKeyName: string;
	s: string;
	buffer: AnsiString;
begin
	//WriteLn;
	//WriteDebug(IntToStr(eventId));
	//WriteLn('ProcessEvent(): ', eventId, Chr(9));
	buffer := la[0] + ' ' + GetEventType(StrToInt(la[5])) + ' eid=' + IntToStr(eventId) + ' ';
	
	for x := 0 to High(la) do
	begin
		// print per line!
		//WriteLn(Chr(9), x, Chr(9), eventId, Chr(9), la[x]);
		
		strKeyName := GetKeyName(eventId, x);
		if Length(strKeyName) > 0 then
		begin
			s := GetKeyName(eventId, x);
			s := s + '=';
			if GetKeyType(eventId, x) = true then
				s := s + Chr(34) + la[x] + Chr(34)
			else
				s := s + la[x];
			
			//WriteLn(Chr(9), Chr(9), s);
			buffer := buffer + s + ' ';
		end;
	end; // of for x := 0 to High(la) do
	
	// Update the counter of processed events.
	EventIncreaseCount(eventId);
	
	//WriteLn('LINE TO WRITE TO SKV: ' + buffer);
	tfSkv.WriteToFile(buffer);
end; // of function ProcessEvent
	

	
procedure ProcessLine(lineCount: integer; l: AnsiString);
{
	Process a line 
}
var
	lineArray: TStringArray;
	//x: integer;
	eventId: integer;
begin
	if Length(l) > 0 then
	begin
		//WriteLn(lineCount, Chr(9), l);
		// Set the lienArray on 0 (Clear it)
		SetLength(lineArray, 0);
		
		// Split the line into the lineArray
		lineArray := SplitString(l, SEPARATOR_PSV);
		
		// Obtain the eventId from the lineArray on position 4.
		eventId := StrToInt(lineArray[4]);	// The Event Id is always found at the 4th position
		
		WriteDebug(IntToStr(lineCount) + Chr(9) + l);
		
		if ProcessThisEvent(eventId) then
			ProcessEvent(eventId, lineArray);
		
		SetLength(lineArray, 0);
	end; // if Length(l) > 0 then
	
	//WriteLn;
end; // of procedure ProcessLine()
	

	
function ConvertFile(pathPsv: string): integer;
var
	pathSplunk: string;
	strLine: AnsiString;			// Buffer for the read line
	intCurrentLine: integer;		// Line counter
	//n: integer;
begin
	// Build the path for the SKV (Splunk) file.
	pathSplunk := StringReplace(pathInput, ExtractFileExt(pathInput), '.skv', [rfReplaceAll, rfIgnoreCase]);
     
	//WriteLn('ConvertFile()');
	WriteLn('Converting ' + pathPsv + ' >>> ' + pathSplunk);
	
	// Delete any existing Splunk file.
	if FileExists(pathSplunk) = true then
	begin
		//WriteLn('WARNING: File ' + pathSplunk + ' found, deleted it.');
		DeleteFile(pathSplunk);
	end;
	
	tfSkv := CTextFile.Create(pathSplunk);
	tfSkv.OpenFileWrite();
	
	tfPsv := CTextFile.Create(pathPsv);
	tfPsv.OpenFileRead();
	repeat
		strLine := tfPsv.ReadFromFile();
		intCurrentLine := tfPsv.GetCurrentLine();
		//WriteLn(intCurrentLine, Chr(9), strLine);
		
		//n := Pos('$|', strLine);	// V04: Check for a computer name (COMPUTERNAME$) in the line (check for $|)
		//if n = 0 Then
			// V04: Only process the lines with no COMPUTERNAME$ in the line.
		ProcessLine(intCurrentLine, strLine);
			
		WriteMod(intCurrentLine, STEP_MOD); // In USupport Library
	until tfPsv.GetEof();
	tfPsv.CloseFile();
	
	tfSkv.CloseFile();
	
	WriteLn;
	
	ConvertFile := RESULT_OK;
end; // of function ConvertFile
	
	
	
//procedure EventRecordAdd(newEventId: word; newDescription: string; newOsVersion: word; newIsActive: boolean); V05
procedure EventRecordAdd(newEventId: word; newDescription: string; newOsVersion: word); // V06
{

	EventId;Description;OsVersion;IsActive

	Add a new record in the array of Event
  
	newEventId      word		The event id to search for
	newDescription  string		Description of the event
	newOsVersion    integer		Integer of version 2003/2008
	newIsActive		boolean		Is this an active event, 
									TRUE	Process this event.
									FALSE	Do not process this event.
									
}
var
	size: integer;
begin
	size := Length(EventArray);
	SetLength(EventArray, size + 1);
	EventArray[size].eventId := newEventId;
	EventArray[size].osVersion := newOsVersion;
	EventArray[size].description := newDescription;
	EventArray[size].count := 0;
	//EventArray[size].isActive := newIsActive;
end; // of procedure EventRecordAdd



procedure EventRecordShow();
var
	i: integer;
begin
	WriteLn();
	WriteLn('EVENTARRAY:');

	for i := 0 to High(EventArray) do
	begin
		//Writeln(IntToStr(i) + Chr(9) + ' ' + IntToStr(EventArray[i].eventId) + Chr(9), EventArray[i].isActive, Chr(9) + IntToStr(EventArray[i].osVersion) + Chr(9) + EventArray[i].description);
		Writeln(IntToStr(i) + Chr(9) + ' ' + IntToStr(EventArray[i].eventId) + Chr(9) + IntToStr(EventArray[i].osVersion) + Chr(9) + EventArray[i].description);
	end;
end; // of procedure EventRecordShow



procedure EventDetailRecordAdd(newEventId: integer; newKeyName: string; newPostion: integer; newIsString: boolean); // V06
{
		
	EventId;KeyName;Position;IsString;IsActive

	Add a new record in the array of EventDetail
  
	newEventId      integer		The event id to search for
	newKeyName  	string		Description of the event
	newPostion  	integer		Integer of version 2003/2008
	newIsString		boolean		Is this a string value
									TRUE	Process as an string
									FALSE	Process this as an number
	newIsActive		boolean		Is tris an active event detail; 
									TRUE=process this 
									FALSE = Do not process this
}
var
	size: integer;
begin
	size := Length(EventDetailArray);
	SetLength(EventDetailArray, size + 1);
	EventDetailArray[size].eventId := newEventId;
	EventDetailArray[size].keyName := newKeyName;
	EventDetailArray[size].position := newPostion;
	EventDetailArray[size].isString := newIsString;
	//EventDetailArray[size].isActive := newIsActive;
	//EventDetailArray[size].convertAction := newConvertAction;
	
end; // of procedure EventDetailRecordAdd



procedure EventDetailRecordShow();
var
	i: integer;
begin
	WriteLn();
	WriteLn('EVENTDETAILARRAY:');

	WriteLn('#', Chr(9), 'event', Chr(9), 'pos', Chr(9), 'isStr', Chr(9), 'keyName');
	
	for i := 0 to High(EventDetailArray) do
	begin
		//WriteLn('record: ' + IntToStr(i));
		Writeln(IntToStr(i), Chr(9), IntToStr(EventDetailArray[i].eventId), Chr(9), IntToStr(EventDetailArray[i].position), Chr(9), EventDetailArray[i].isString, Chr(9), EventDetailArray[i].keyName);
	end;
end; // of procedure EventRecordShow



procedure ReadEventDefinitionFile(p : string);
var
	//strEvent: string;
	//intEvent: integer;
	//strFilename: string;
	tf: CTextFile; 		// Text File
	l: string;			// Line Buffer
	x: integer;			// Line Counter
	a: TStringArray;	// Array
begin
	//WriteLn('ReadEventDefinitionFile: ==> ', p);
	
	//WriteLn(ExtractFileName(p)); // Get the file name with the extension.
	
	// Get the file name from the path p.
	//strFilename := ExtractFileName(p);
	
	//WriteLn(ExtractFileExt(p));
	// Get the event id from the file name by removing the extension from the file name.
	//strEvent := ReplaceText(strFilename, ExtractFileExt(p), '');
	
	//WriteLn(strEvent);
	// Convert the string with Event ID to a integer.
	//intEvent := StrToInt(strEvent);
	//WriteLn(intEvent);
	
	
	
	//WriteLn('CONTENTS OF ', p);
	tf := CTextFile.Create(p);
	tf.OpenFileRead();
	repeat
		l := tf.ReadFromFile();
		If Length(l) > 0 Then
		begin
			//WriteLn(l);
			x := tf.GetCurrentLine();
			a := SplitString(l, SEPARATOR_CSV);
			if x = 1 then
			begin
				//WriteLn('FIRST LINE!');
				//WriteLn(Chr(9), l);
				//EventRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3])); // V05
				EventRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2])); // V06
			end
			else
			begin
				//WriteLn('BIGGER > 1');
				//WriteLn(Chr(9), l);
				//EventDetailRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3]), StrToBool(a[4]), a[5]); // V05
				EventDetailRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3])); // V06
			end;
			//WriteLn(x, Chr(9), l);
		end;
	until tf.GetEof();
	tf.CloseFile();
	
	//WriteLn;
end; // of procedure ReadEventDefinitionFile



procedure ReadEventDefinitionFiles();
var	
	sr : TSearchRec;
	count : Longint;
begin
	count:=0;
	
	SetLength(EventArray, 0);
	SetLength(EventDetailArray, 0);
	
	if FindFirst(GetProgramFolder() + '\*.evd', faAnyFile and faDirectory, sr) = 0 then
    begin
    repeat
		Inc(count);
		with sr do
		begin
			ReadEventDefinitionFile(GetProgramFolder() + '\' + name);
        end;
		until FindNext(sr) <> 0;
    end;
	FindClose(sr);
	Writeln ('Found ', count, ' event definitions to process.');
end; // of procedure ReadAllEventDefinitions

	
	
procedure ProgramTitle();
begin
	WriteLn();
	WriteLn(StringOfChar('-', 120));
	WriteLn(UpperCase(GetProgramName()) + ' -- Version: ' + VERSION + ' -- Unique ID: ' + ID);
	WriteLn(DESCRIPTION);
	WriteLn(StringOfChar('-', 120));	
end; // of procedure ProgramTitle()



procedure ProgramUsage();
var
	p:	string;
begin
	p := ParamStr(0);

	WriteLn();
	WriteLn('--debug, -d:             Debug on');
	WriteLn('--help, -h, -?:          Show the help');
	WriteLn('[psv file to convert]:   File to convert in Pipe Seperated Values (PSV) format');
	WriteLn();
	WriteLn('Usage:');
	WriteLn(p + ' [psv file to convert] [switches]');
	WriteLn();
end; // of procedure ProgramUsage()



procedure ProgramTest();
//var 
//	x	: integer;
begin
	//EventReadConfig();
	// EventRecordShow();
	
	//EventDetailReadConfig();
	// EventDetailRecordShow();
	
	//WriteLn(ProcessThisEvent(675));
	
	//EventFoundIncrease(4767);
	
	SetLength(EventFound, 1);
	WriteLn('High of EventFound=', High(EventFound));
	{
	for x := 0 To High(EventFound) do
	begin
		WriteLn(
	end;
	}
	// SetLength(EventFound, 0);
	EventFoundAdd(4767);
	//EventFoundIncrease(4767);
	EventFoundAdd(2344);
	
	EventFoundStats();
	
end; // of procedure ProgramTest()



procedure ProgramInit();
var	
	i: integer;
begin
	// Process the parameters
	
	//WriteLn('ProgramInit()');
	//WriteLn('ParamCount: ', ParamCount);
	
	ProgramTitle();
	
	if ParamCount = 0 then
	begin
		ProgramUsage();
		Halt(0);
	end
	else
	begin
		for i := 1 to ParamCount do
		begin
			//Writeln(i, ': ', ParamStr(i));
			
			case LowerCase(ParamStr(i)) of
				'--debug', '-d':	
					begin
						blnDebug := true;
						WriteLn('Debug is ON!');
					end;
				'--help', '-h', '-?':
					begin
						ProgramUsage();
						Halt(0);
					end;
			else
				pathInput := ParamStr(i)
			end;
		end; 
	end;
	//for I := 1 to ParamCount do
    //WriteLn('Param ', I, ': ', ParamStr(I));
end; // of procedure ProgramInit()



procedure ProgramRun();
var
	pathLog: string;
begin
	pathInput := ParamStr(1);
    
	//WriteLn('Path input:  ' + pathInput);
    
	if FileExists(pathInput) = false then
	begin
		programResult := RESULT_ERR_INPUT;
		WriteLn('WARNING: File ' + pathInput + ' not found.');
	end
	else
	begin
		// Read all event definition files in the array.
		ReadEventDefinitionFiles();
		
 		//EventReadConfig();
		EventRecordShow();
		
		// V07: Open a log file to write processed file and statistics
		pathLog := LeftStr(GetProgramPath(), Length(GetProgramPath()) - 4) + '.log';
		//WriteLn('pathLog: ' + pathLog);
			
		// Delete any existing Splunk file.
		if FileExists(pathLog) = true then
		begin
			DeleteFile(pathLog);
		end;
			
		tfLog := CTextFile.Create(pathLog);
		tfLog.OpenFileWrite();
			
		tfLog.WriteToFile('Input: ' + pathInput);
		tfLog.WriteToFile('');
			
		programResult := ConvertFile(pathInput);
		if programResult <> 0 then
		begin
			programResult := RESULT_ERR_CONV;
			WriteLn('WARNING: No conversion done.');
		end;
			
		ShowStatistics();
			
		tfLog.CloseFile();
	end
end; // of procedure ProgramRun()



procedure ProgramDone();
begin
	

	WriteLn('Program halted (', programResult, ')');
	Halt(programResult)	
end; // of procedure ProgramDone()



begin
	ProgramInit();
	//ProgramTest();
	ProgramRun();
	ProgramDone();
end. // of program PSV2SKV
