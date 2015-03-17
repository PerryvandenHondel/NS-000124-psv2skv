{ =====================================================================================================================

	PROGRAM:
		psv2skv.exe

	DESCRIPTION:
		Convert a PSV (Pipe Separated Values) output text file to an Splunk Key-Value text file to be indexed
  
	VERSION:
		05	2015-03-16	PVDH	Modifications:
								1) Renamed the standard event_id key to evtid
		04	2015-03-11	PVDH	Modifications:
								1) Do not process computer accounts in account field to reduce log size.
								   Changed in function ConvertFile()
		03	2015-03-10	PVDH	Modifications
		02	2015-03-03	PVDH	Modifications
		01	2014-10-29	PVDH	Initial version

	RETURNS
		RESULT_OK			0   OK, see 'output.skv'
		RESULT_ERR_CONV		1   No conversion done
		RESULT_ERR_INPUT	2   Input PSV file not found
		RESULT_ERR_CONF_E	3	Error in config file Event
		RESULT_ERR_CONF_ED	4	Error in config file EventDetail
	
 =====================================================================================================================} 


program psv2skv;


{$mode objfpc}
{$H+}


uses
	Classes, 
	Sysutils,
	UTextFile,
	USplunkFile,
	USupportLibrary;
	
	
const
	ID 					=	'000124';
	VERSION 			=	'04';
	DESCRIPTION 		=	'Convert PSV (Pipe Separated Values) Event Log to SKV (Splunk Key-Values) format, based on config settings';
	RESULT_OK			=	0;
	RESULT_ERR_CONV		=	1;
	RESULT_ERR_INPUT	=	2;
	RESULT_ERR_CONF_E	=	3;
	RESULT_ERR_CONF_ED	=	4;
	SEPARATOR_PSV		=	'|';	
	SEPARATOR_CSV		=	';';
	STEP_MOD			=	37;		// Step modulator for echo mod, use a off-number, not rounded as 10, 15 etc. to see the changes.
	
	
type
	// Type definition of the Event Records
	TEventRecord = record
		eventId: integer;
		description: string;
		count: integer;
		osVersion: word;
		isActive: boolean;			//	Is this an active event to process? True=Process/False=Do not process
	end;
	TEventArray = array of TEventRecord;

	TEventDetailRecord = record
		eventId: integer;           // Event number
		keyName: string;            // Key name under Splunk
		position: word;       	   	// Position in the Logparser string
		isString: boolean;          // Save value as string (True=String, False=number)
		isActive: boolean;       	// Process this position (True=process, False=Do not process)
		convertAction: string;		// If the read value needs conversion, mention it in this field.
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
			//WriteLn('FOUND ', e, ' ON POS ', i);
			// Found the event e in the array, return the isActive state
			r := EventArray[i].isActive;
			break;
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
				if EventDetailArray[i].isActive = true then
				begin
					//WriteLn('FOUND FOR EVENTID ', eventId, ' AND ACTIVE KEYNAME ON POSITION ', position);
					r := EventDetailArray[i].keyName;
				end;
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
			begin
				if EventDetailArray[i].isActive = true then
				begin
					//WriteLn('FOUND FOR EVENTID ', eventId, ' AND ACTIVE KEYNAME ON POSITION ', position);
					r := EventDetailArray[i].isString;
				end;
			end;
		end;
	end;
	GetKeyType := r;
end; // of function GetKeyType	
	

	
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
	WriteLn();
	WriteLn('Evt', Chr(9), 'Number', Chr(9), 'Description');
	WriteLn('----', Chr(9), '------', Chr(9), '--------------------------------------');
	
	for i := 0 to High(EventArray) do
	begin
		//WriteLn('record: ' + IntToStr(i));
		Writeln(EventArray[i].eventId:4, Chr(9), EventArray[i].count:6, Chr(9), EventArray[i].description, ' (', EventArray[i].osVersion, ')');
		totalEvents := totalEvents + EventArray[i].count;
	end;
	WriteLn;
	WriteLn('Total of events ', totalEvents, ' converted.');
	
	WriteLn;
	
	WaitSecs(5);
	
end; // of procedure ShowStatistics
	

	
procedure ProcessEvent(eventId: integer; la: TStringArray);
var
	x: integer;
	strKeyName: string;
	s: string;
	buffer: AnsiString;
begin
	buffer := la[0] + ' ' + GetEventType(StrToInt(la[5])) + ' eid=' + IntToStr(eventId) + ' ';
	
	for x := 0 to High(la) do
	begin
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
end;
	

	
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
		
		eventId := StrToInt(lineArray[4]);
		//Writeln(lineCount, Chr(9), l);
		//WriteLn(Chr(9), eventId);
		
		if ProcessThisEvent(eventId) then
		begin
			//WriteLn(lineCount, ' >>>>> EVENT FOUND TO BE CONVERTED: ', eventId);
			ProcessEvent(eventId, lineArray);
			//WriteMod(lineCount, 37); // In USupport Library
			
		end; // if ProcessThisEvent(eventId) then
		
		{
		for x := 0 to Length(lineArray) do
		begin
			WriteLn(Chr(9), x, ':', Chr(9), lineArray[x]);
		end;		
		}
		SetLength(lineArray, 0);
	end; // if Length(l) > 0 then
	
	//WriteLn;
end; // of procedure ProcessLine()
	

	
function ConvertFile(pathPsv: string): integer;
var
	pathSplunk: string;
	strLine: AnsiString;			// Buffer for the read line
	intCurrentLine: integer;		// Line counter
	n: integer;
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
		
		n := Pos('$|', strLine);	// V04: Check for a computer name (COMPUTERNAME$) in the line (check for $|)
		if n = 0 Then
			// V04: Only process the lines with no COMPUTERNAME$ in the line.
			ProcessLine(intCurrentLine, strLine);
			
		WriteMod(intCurrentLine, STEP_MOD); // In USupport Library
	until tfPsv.GetEof();
	tfPsv.CloseFile();
	
	tfSkv.CloseFile();
	
	WriteLn;
	
	ConvertFile := RESULT_OK;
end; // of function ConvertFile
	
	
	
procedure EventRecordAdd(newEventId: word; newDescription: string; newOsVersion: word; newIsActive: boolean);
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
	EventArray[size].isActive := newIsActive;
end; // of procedure EventRecordAdd



procedure EventRecordShow();
var
	i: integer;
begin
	WriteLn();
	WriteLn('EVENTARRAY:');

	for i := 0 to High(EventArray) do
	begin
		Writeln(IntToStr(i) + Chr(9) + ' ' + IntToStr(EventArray[i].eventId) + Chr(9), EventArray[i].isActive, Chr(9) + IntToStr(EventArray[i].osVersion) + Chr(9) + EventArray[i].description);
	end;
end; // of procedure EventRecordShow



procedure EventReadConfig();
var
	pathEvent: string;
	l: string;
	a: TStringArray;
	tfEvent: CTextFile; 
begin
	pathEvent := LowerCase(GetProgramName());
	pathEvent := StringReplace(pathEvent, ExtractFileExt(pathEvent), '-event.csv', [rfReplaceAll, rfIgnoreCase]);
	
	//WriteLn('EventReadConfig()');
	WriteLn('Reading event master from: ' + pathEvent);
	
	if FileExists(pathEvent) = true then
	begin
		//Writeln('Configuration file ', pathEvent, ' found');
		
		SetLength(eventArray, 0);
		tfEvent := CTextFile.Create(pathEvent);
		tfEvent.OpenFileRead();
		repeat
			l := tfEvent.ReadFromFile();
			a := SplitString(l, SEPARATOR_CSV);
			if (tfEvent.GetCurrentLine() > 1) then
			begin
				// EventId;Description;OsVersion;IsActive
				EventRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3]));
			end
		until tfEvent.GetEof();
		tfEvent.CloseFile();
	end
	else
	begin
		WriteLn('WARNING: Configuration file ' + pathEvent + ' not found!');
		Halt(RESULT_ERR_CONF_E);
	end; // if FileExists
end; // of procedure EventReadConfig()



procedure EventDetailRecordAdd(newEventId: integer; newKeyName: string; newPostion: integer; newIsString: boolean; newIsActive: boolean; newConvertAction: string);
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
	EventDetailArray[size].isActive := newIsActive;
	EventDetailArray[size].convertAction := newConvertAction;
	
end; // of procedure EventDetailRecordAdd



procedure EventDetailRecordShow();
var
	i: integer;
begin
	WriteLn();
	WriteLn('EVENTDETAILARRAY:');

	WriteLn('#', Chr(9), 'event', Chr(9), 'pos', Chr(9), 'isStr', Chr(9), 'isAct', Chr(9), 'keyName');
	
	for i := 0 to High(EventDetailArray) do
	begin
		//WriteLn('record: ' + IntToStr(i));
		Writeln(IntToStr(i), Chr(9), IntToStr(EventDetailArray[i].eventId), Chr(9), IntToStr(EventDetailArray[i].position), Chr(9), EventDetailArray[i].isString, Chr(9), EventDetailArray[i].isActive, Chr(9), EventDetailArray[i].keyName, ' (Convert=',  EventDetailArray[i].convertAction, ')');
	end;
end; // of procedure EventRecordShow



procedure EventDetailReadConfig();
var
	pathEvent: string;
	l: string;
	a: TStringArray;
	tfEvent: CTextFile; 
begin
	pathEvent := LowerCase(GetProgramName());
	pathEvent := StringReplace(pathEvent, ExtractFileExt(pathEvent), '-event-detail.csv', [rfReplaceAll, rfIgnoreCase]);
	
	//WriteLn('EventDetailReadConfig()');
	WriteLn('Reading event detail from: ' + pathEvent);
	
	if FileExists(pathEvent) = true then
	begin
		//Writeln('Configuration file ', pathEvent, ' found');
		
		SetLength(EventDetailArray, 0);
		tfEvent := CTextFile.Create(pathEvent);
		tfEvent.OpenFileRead();
		repeat
			l := tfEvent.ReadFromFile();
			if Length(l) > 0 then
			begin
				// Only process lines with data.
				//WriteLn(Chr(9), l);
				a := SplitString(l, SEPARATOR_CSV);
				if (tfEvent.GetCurrentLine() > 1) then
				begin
					// Skip first header line, and read every next line.
					// EventId;KeyName;Position;IsString;IsActive;ConvertAction
					EventDetailRecordAdd(StrToInt(a[0]), a[1], StrToInt(a[2]), StrToBool(a[3]), StrToBool(a[4]), a[5]);
				end;
			end;
		until tfEvent.GetEof();
		tfEvent.CloseFile();
	end
	else
	begin
		WriteLn('WARNING: Configuration file ' + pathEvent + ' not found!');
		Halt(0);
	end; // if FileExists
end; // of procedure ReadConfigEvent()

	
	
procedure ProgramTitle();
begin
	WriteLn();
	WriteLn(StringOfChar('-', 120));
	WriteLn(UpperCase(GetProgramName()) + ' -- Version: ' + VERSION + ' -- Unique ID: ' + ID);
	WriteLn(DESCRIPTION);
	WriteLn(StringOfChar('-', 120));	
end; // of procedure ProgramTitle()



procedure ProgramUsage();
begin
	WriteLn();
	WriteLn('Usage:');
	WriteLn(Chr(9) + ParamStr(0) + ' <full-path-to-infile.psv>');
	WriteLn();
	WriteLn('Creates a new converted text Splunk file (full-path-to-infile.psv >> full-path-to-infile.skv)');
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
begin

end; // of procedure ProgramInit()



procedure ProgramRun();
begin
	ProgramTitle();
	
	if ParamCount = 1 then
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
			//WriteLn('INFO: File ' + pathInput + ' found, start conversion');
	 		EventReadConfig();
			//EventRecordShow();
			
			EventDetailReadConfig();
			//EventDetailRecordShow();
			
			programResult := ConvertFile(pathInput);
			if programResult <> 0 then
			begin
				programResult := RESULT_ERR_CONV;
				WriteLn('WARNING: No conversion done.');
			end;
		end
	end
	else
	begin
		ProgramUsage();
		programResult := RESULT_OK;
	end;
end; // of procedure ProgramRun()



procedure ProgramDone();
begin
	ShowStatistics();

	WriteLn('Program halted (', programResult, ')');
	Halt(programResult)	
end; // of procedure ProgramDone()



begin
	ProgramInit();
	//ProgramTest();
	ProgramRun();
	ProgramDone();
end. // of program PSV2SKV
