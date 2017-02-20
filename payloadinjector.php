<?php

/**
 * Payload injector to add payload to Tiny Download app without invalidating its signature
 *
 * @author  Ravi Potluri <rpotluri>
 *
 */
class PI {

    /**
     * File handle for the source exe file
     *
     * @var string
     * @access private
     */
    private $fh_src;

    /**
     * File handle for the destination exe file
     *
     * @var string
     * @access private
     */
    private $fh_dst;

    /**
     * File size of the source exe file
     *
     * @var string
     * @access private
     */
    private $src_size = 0;

    /**
     * Size of the injection string or payload string
     *
     * @var string
     * @access private
     */
    private $inj_size = 0;

    /**
     * Source file buffer
     *
     * @var string
     * @access private
     */
    private $src_buffer;

    /**
     * Injection buffer
     *
     * @var string
     * @access private
     */
    private $inj_buffer;

    /**
     * Destination buffer
     *
     * @var string
     * @access private
     */
    private $dst_buffer = 0;

    /**
     * PE Header for the exe file
     *
     * @var string
     * @access private
     */
    private $PEHeader = 0;

    /**
     * PE Security for the source exe file
     *
     * @var string
     * @access private
     */
    private $PESecurity = 0;

    /**
     * Security address entry in exe file
     *
     * @var string
     * @access private
     */
    private $SEC_addr = 0;

    /**
     * Security entry size in exe file
     *
     * @var int
     * @access private
     */
    private $SEC_size = 0;

    /**
     * 
     * 
     * Write buffer to a file using file handle
     * 
     * @param string $fh file handle
     * @param int    $arg2 buffer to write to the file handle
     *
     * @return  void
     *
     */
    function write_to_file($fh, $buffer) {
        fwrite($fh, $buffer);
    }

    /**
     * 
     * 
     * Set debug to true or false. always false on production
     * 
     * @param bool $flag flag to set debug to true or false
     *
     * @return  void
     * @access public
     */
    function is_debug($flag = false) {
        if ($flag) {
            ini_set('display_errors', '1');
        }
    }

    /**
     * 
     * 
     * Open file with file handle, name and mode
     * 
     * @param string $ref_fh file handle
     * @param string $name file name
     * @param string $mode mode of the file r, w, a
     * 
     *
     * @return  void
     *
     */
    function open_file($name, $mode) {
        $open_mode = substr($mode, 0, 1);
        $file_mode = substr($mode, 1, 1);

        $omode = ' ';
        switch ($open_mode) {
            case 'r' : $omode = '<';
                break;
            case 'w' : $omode = '>';
                break;
            case 'a' : $omode = '>>';
                break;
        }
        $fmode = ( $file_mode == 'b' ) ? 1 : 0;
        if ($omode == ' ') {
            die("Bad file mode specified in download_app.exe open_file! Use r, w, a with t(text) and b(binary)\n. Please contact your administrator for help.");
        }


        $this->fh_src = fopen($name, "$mode") or die("The required file download_app.exe isn’t available on the server.  Please contact your administrator for help.");
    }

    /**
     * 
     * 
     * Close source file and destination file using 
     * the source and destination file handles.
     * 
     * 
     *
     * @return  void
     *
     */
    function close_file() {

        close_file($this->fh_src);
        close_file($this->fh_dst);
    }

    /**
     * 
     * 
     * Read file
     * 
     * 
     * @param int    $filename name of file
     * 
     *
     * @return  void
     *
     */
    function read_file($filename) {
        //if defined $ref_fs && defined $fh;
        $this->src_size = filesize($filename);
        $this->src_buffer = fread($this->fh_src, $this->src_size);
        return $this->src_buffer;
    }

    /**
     * 
     * 
     * Validate input file
     * 
     *
     * @return  void
     *
     */
    function validate_input_file() {
        $fdata = substr($this->src_buffer, 60, 4);
        $this->PEHeader = unpack("I", $fdata);
        $this->PEHeader = $this->PEHeader[1];
        $fdata = substr($this->src_buffer, $this->PEHeader, 4);
        //check if file is PE32 or PE32+
        $fdata = substr($this->src_buffer, $this->PEHeader + 24, 2);
        $PE32plus = unpack("v", $fdata);
        $PE32plus = $PE32plus[1];
        $PE32plus = ( $PE32plus == 0x20B ) ? 1 : 0;
        //gets the SECURITY _IMAGE_DATA_DIRECTORY entry
        $this->PESecurity = $this->PEHeader + 24 + 128 + $PE32plus * 16;
        $fdata = substr($this->src_buffer, $this->PESecurity, 4);
        $this->SEC_addr = unpack("I", $fdata);
        $this->SEC_addr = $this->SEC_addr[1];
        $fdata = substr($this->src_buffer, $this->PESecurity + 4, 4);
        $this->SEC_size = unpack("I", $fdata);
        $this->SEC_size = $this->SEC_size[1];
        return 1;
    }

    /**
     * 
     * 
     * Compute checksum
     * 
     * @param string $buffer source file buffer
     * @param int    $buffer_size buffer size
     * @param int    $checksum_pos checksum position in final exe
     *
     * @return  void
     *
     */
    function compute_checksum($buffer, $buffer_size, $checksum_pos) {

        $checksum = 0;
        $limit = pow(2, 32);
        $size = $buffer_size / 4;
        for ($i = 0; $i < $size; $i++) {
            if ($i * 4 == $checksum_pos) {

                $fdata = substr($buffer, $i * 4, 4);
                $dword = unpack("I", $fdata);
                $dword = $dword[1];
                $checksum = ( $checksum & 0xffffffff ) + $dword + ( $checksum >> 32 );
                if ($checksum > $limit) {
                    $checksum = ( $checksum & 0xffffffff ) + ( $checksum >> 32 );
                }
            }
        }
        $checksum = ( $checksum & 0xffff ) + ( $checksum >> 16 );
        $checksum = $checksum + ( $checksum >> 16 );
        $checksum = $checksum & 0xffff;
        $checksum += $buffer_size;
        return $checksum;
    }

    /**
     * 
     * 
     * Inject payload to the source exe buffer
     * 
     * @param bool $padding flag to padding to add to the file
     * @param int  $caculate_checksum flag to calculate checksum or not
     *
     * @return  void
     *
     */
    public function get_payload_from_url() {

        $this->inj_buffer = $_GET['payload'] . "==end8274==";
        if (!isset($this->inj_buffer)) {
            die("No Payload passed to the payload injector. Please contact your administrator for help.");
        }
    }

    /**
     * 
     * 
     * Inject payload to the source exe buffer
     * 
     * @param bool $padding flag to padding to add to the file
     * @param int  $caculate_checksum flag to calculate checksum or not
     *
     * @return  void
     *
     */
    function inject($padding, $calculate_checksum) {

        $newline = "\n";

        $this->inj_size = strlen($this->inj_buffer);
        if (( strlen($this->inj_buffer) % 8) != 0) {
            if (!$padding) {
                print "Warning: injection file strlen is not a multiple of 8; you should use --paddata\n";
            } else {
                $pad_size = 8 - ( strlen($this->inj_buffer)) % 8;
                $this->inj_buffer = str_repeat(chr(0), $pad_size) . $this->inj_buffer; //chr(0)
                $this->inj_size += $pad_size;
            }
        }
        // writes the destination file
        $this->dst_buffer = $this->src_buffer . $this->inj_buffer;
        $this->write_to_file($this->fh_dst, $this->dst_buffer);
        // expands the size of the file signature
        $this->SEC_size += $this->inj_size;
        $new_size = pack("I", $this->SEC_size);
        fseek($this->fh_dst, $this->PESecurity + 4, 0);
        fwrite($this->fh_dst, $new_size);
        $buffer_size = strlen($this->dst_buffer);
        // sets the checksum
        $buffer2 = substr($this->dst_buffer, 0, $this->PESecurity + 4) . $new_size . substr($this->dst_buffer, $this->PESecurity + 8, $buffer_size - $this->PESecurity - 8);
        $checksum = 0;
        if ($calculate_checksum) {
            $checksum = $this->compute_checksum($buffer2, $buffer_size, $this->PEHeader + 88);
        }

        $new_checksum = pack("I", $checksum);
        fseek($this->fh_dst, $this->PEHeader + 88, 0);
        fwrite($this->fh_dst, $new_checksum);
        return 1;
    }

    /**
     * 
     * 
     * Open temp file and write
     *
     * @return  void
     *
     */
    public function open_temp_file() {
        $this->tmpName = tempnam(sys_get_temp_dir(), 'data');
        $this->fh_dst = fopen($this->tmpName, 'w') or die("Failed! Error while opening temp file\n. Please contact your administrator for help.");
    }

    /**
     * 
     * 
     * Download temp file
     * 
     *
     * @return  void
     *
     */
    public function download_temp() {
        header('Content-Description: File Transfer');
        header('Content-Disposition: attachment; filename=result.exe');
        header('Content-Transfer-Encoding: binary');
        header("Content-Type: application/octet-stream");
        header('Expires: 0');
        header('Cache-Control: must-revalidate');
        header('Pragma: public');
        header('Content-Length: ' . filesize($this->tmpName));
        ob_clean();
        flush();
        readfile($this->tmpName);
        unlink($this->tmpName);
    }

}



$pi = new PI();
$pi->is_debug(false);
$src_app_name = 'download_app.exe';
$pi->open_file($src_app_name, 'r');
$pi->open_temp_file();
$pi->read_file($src_app_name) or die("Failed! Error while processing file download_app.exe\n. Please contact your administrator for help.");
//Makes sure the signed file is a valid EXE file
$pi->validate_input_file() or die("Failed! download_app.exe is not a valid, signed EXE file\n. Please contact your administrator for help.");
$pi->get_payload_from_url();
//first param is to pad, second is compute checksum both true
$pi->inject(true, true);
$pi->download_temp();
$pi->close_file();
