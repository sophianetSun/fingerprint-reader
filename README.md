# fignerprint-reader
WaveShare UART Fingerprint reader for use of raspberry pi

## Protocol Align

* Dormant State
* Set / Read mode 
	* (repeat mode / prohibit mode)
* Add Fingerprint 
	* must 3 times input(required send command)
	* user number range 1 - 0xFFF(4095)
	* user ID and user privilege should be same
* Delete User
* Delete All Users
* Acquire the total number of users
* Compare 1:1
* Compare 1:N
* Acquire user privilege
* Acquire DSP module version
* Set Read Comparison level (level range is 0-9, default 5)
* Acquire and upload images
* Upload acquired images and extract eigenvalue
* Download eigenvalues and acquire fingerprint comparison
* Download the fingerprint eigenvalues and DSP module database fingerprint compare 1:1
* Download the fingerprint eigenvalues and DSP module database compare 1:N
* Upload the DSP module database specified user eigenvalue
* 18) Download the eigenvalue and save to the DSP module database according to the specified user number
* 19) Acquire all logged in user numbers and user privilege
* 25) Set/Read fingerprint capture timeout value 
	* Range of waiting timeout value is 0-255 (0 is wait infinitely or time * 0.2s)

## Process

* Add
	* Start
		* 1st Cycle
		* Check Database ; if not: Return Q3=ST_FULL
		* Collect Fingerprint ; if not: Q3=ST_TIMEOUT
		* Image Processing ; if not: Q3=ST_FAIL
		* If yes; Q3=ST_SUCCESS
		* 2nd
		* Collect Fingerprint
		* Image Processing
		* OK
		* 3th
		* Collect Fingerprint
		* Image Processing
		* Check Unique FP(only prohibit); Q3=ST_USER_EXIST
		* Add FP database
		* Q3=ST-SUCCESS
	* Delete
	* Delete All
	* Upload Image and Extract eigenvalue
		* Collect
		* Img Process
		* Return data with eigenvalue
