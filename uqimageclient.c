/* uqimageclient.c
 *
 * Written by Alvin Benny
 *
 * The uqimageclient program provides a command line interface that allows
 * interaction with the server (uqimageproc). As a client it performs
 * connecting, sending an image to be operated on, receiving the modified image
 * back from the server and saving it to a file.
 */
#include <csse2310a4.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <signal.h>

#define BUFFER_SIZE 1024

// Program Paramaters
typedef struct {
    const char* port;
    const char* inFile;
    int rotate;
    int width;
    int height;
    char orientation;
    const char* outFile;
} ProgParams;

// Command line option arguments
const char* const inFileArg = "--in";
const char* const rotateArg = "--rotate";
const char* const scaleArg = "--scale";
const char* const flipArg = "--flip";
const char* const outFileArg = "--output";

const char* const errorUsage
        = "Usage: uqimageclient portnum [--in infilename] [--rotate degrees | "
          "--scale w h | --flip orientation] [--output outfile]\n";

// Specified constraints
typedef enum {
    ROTATE_MIN = -359,
    ROTATE_MAX = 359,
    WIDTH_MAX = 10000,
    HEIGHT_MAX = 10000,
} Constraints;

// Exit codes
typedef enum {
    OK = 0,
    USAGE_ERROR = 9,
    READ_ERROR = 17,
    WRITE_ERROR = 8,
    PORT_ERROR = 18,
    NO_IMAGE_DATA = 2,
    NO_RESPONSE = 4,
    WRITE_RESPONSE_ERROR = 10,
    NOT_OK_RESPONSE = 20
} ExitStatus;

#define HTTP_OK_STATUS 200

// Structure to hold read/write FDs
typedef struct {
    int inFD;
    int outFD;
} FileInfo;

// Prints usage error
void usage_error()
{
    fprintf(stderr, errorUsage);
    exit(USAGE_ERROR);
}

/* sigpipe_handler()
 * Setups signal handler for SIGPIPE to ignore the signal so the client
 * can gracefully exit when receiving it.
 */
void sigpipe_handler()
{
    struct sigaction sa; // struct to hold signal settings
    sa.sa_handler = SIG_IGN; // Set handler to ignore signal
    sa.sa_flags = 0; // Prevent special behaviour i.e., automatic restart
    // Use NULL to discard previous action settings for SIGPIPE
    sigaction(SIGPIPE, &sa, NULL); // Apply confirguation to SIGPIPE
}

/* check_port()
 * Ensures a port number is provided by checking argument count and length
 *
 * argc: The number of command line arguments
 * argv: An array of the command line arguments
 */
const char* check_port(int argc, char* argv[])
{
    if (argc < 2) { // Ensure port number is provided
        usage_error();
    }
    if (!(strlen(argv[1]) > 0)) { // Port number argument is non empty
        usage_error();
    }
    char* port = argv[1];

    return port;
}

/* handle_prefix()
 * Removes leading plus sign from a numeric string if present
 *
 * arg: A pointer to the string that may start with a plus sign
 *
 * returns: The pointer to the string after incrementing it by 1 if it contains
 * the plus sign
 */
char* handle_prefix(char* arg)
{
    if (arg[0] == '+') {
        arg = arg + 1;
    }
    return arg;
}

/* process_cmds()
 * Sets parameters based on command line arguments and existing constraints
 *
 * argc: The number of command-line arguments
 * argv: An array of the command line argments
 *
 * returns: A struct containing the configuation from the command line
 * arguments
 */
ProgParams process_cmds(int argc, char* argv[])
{
    ProgParams params = {NULL, NULL, 0, 0, 0, '\0', NULL};
    int optionCount = 0;
    params.port = check_port(argc, argv);
    for (int i = 2; i < argc; i++) {
        // If input file is specified
        // check if the second argument exists and is not an empty string
        if (strcmp(argv[i], inFileArg) == 0 && i + 1 < argc
                && strlen(argv[i + 1]) > 0 && !params.inFile) {
            params.inFile = argv[++i];
        } else if (strcmp(argv[i], rotateArg) == 0 && i + 1 < argc
                && !params.rotate) {
            params.rotate = atoi(handle_prefix(argv[++i]));
            if (strcmp(argv[i], "0") != 0 && params.rotate == 0) {
                usage_error();
            }
            if (params.rotate < ROTATE_MIN || params.rotate > ROTATE_MAX) {
                usage_error();
            }
            optionCount++;
            // Ensure both provided arguments are positive integers
        } else if (strcmp(argv[i], scaleArg) == 0 && i + 2 < argc
                && atoi(handle_prefix(argv[i + 1]))
                && atoi(handle_prefix(argv[i + 2])) && !params.width
                && !params.height) {
            params.width = atoi(handle_prefix(argv[++i]));
            params.height = atoi(handle_prefix(argv[++i]));
            if (params.width > WIDTH_MAX || params.height > HEIGHT_MAX
                    || params.width <= 0 || params.height <= 0) {
                usage_error();
            }
            optionCount++;
        } else if (strcmp(argv[i], flipArg) == 0 && i + 1 < argc
                && strlen(argv[i + 1]) == 1
                && (argv[i + 1][0] == 'h' || argv[i + 1][0] == 'v')
                && params.orientation == '\0') {
            params.orientation = argv[++i][0];
            optionCount++;
        } else if (strcmp(argv[i], outFileArg) == 0 && i + 1 < argc
                && strlen(argv[i + 1]) > 0 && !params.outFile) {
            params.outFile = argv[++i];
        } else {
            usage_error();
        }
    }
    if (optionCount > 1) {
        usage_error();
    }
    return params;
}

/* file_open_error()
 * Prints stderr if a file is unable to opened for reading or writing
 *
 * filename: name of the file being processed
 * mode: string describing the operation i.e., "reading" or "writing"
 */
void file_open_error(const char* filename, const char* mode)
{
    fprintf(stderr, "uqimageclient: unable to open file \"%s\" for %s\n",
            filename, mode);
    if (mode[0] == 'r') {
        exit(READ_ERROR);
    } else {
        exit(WRITE_ERROR);
    }
}

/* verify_files()
 * Verifies that the provided input and output files can be opened
 *
 * inFile: provided input file name
 * outFile: provided output file name
 *
 * returns: A struct containing the file descriptors for input and output files
 */
FileInfo verify_files(const char* inFile, const char* outFile)
{
    FileInfo files = {-1, -1}; // Default is -1 for unopened
    if (inFile) { // if an input file was provided
        files.inFD = open(inFile, O_RDONLY);
        if (files.inFD == -1) { // failed to open
            file_open_error(inFile, "reading");
        }
    }
    if (outFile) {
        // S_IRUSR... Set read and write permissions for the owner
        files.outFD = open(
                outFile, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
        if (files.outFD == -1) {
            file_open_error(outFile, "writing");
        }
    }
    return files;
}

// Based on net2.c from week 9
/* verify_port()
 * Verifies specified port and established a TCP connection using a new socket
 *
 * port: String representing port number or valid service name
 * socketFD: A pointer to an integer that will be set with the file descriptor
 * for the newly created socket
 *
 * returns: Integer status 0 if connection is successful else non zero
 */
int verify_port(const char* port, int* socketFD)
{
    struct addrinfo hints, *ai = NULL; // Structure for storing address/results
    memset(&hints, 0, sizeof(hints)); // initialise hints structure to 0
    hints.ai_family = AF_INET; // Use IPv4
    hints.ai_socktype = SOCK_STREAM; // SOCK_STREAM for TCP

    // Translte hostname "localhost" and given port number into address info
    int err;
    if ((err = getaddrinfo("localhost", port, &hints, &ai))) {
        return PORT_ERROR;
    }

    // Create socket for TCP/IP communication using resolved address family,
    // socket type, and protocol 0 (default)
    *socketFD = socket(AF_INET, SOCK_STREAM, 0);
    if (*socketFD == -1) {
        freeaddrinfo(ai);
        return PORT_ERROR;
    }

    // Connect to first resolved network address using socket
    if (connect(*socketFD, ai->ai_addr, ai->ai_addrlen) == -1) {
        close(*socketFD);
        freeaddrinfo(ai);
        return PORT_ERROR;
    }

    // If connection is successful
    freeaddrinfo(ai);
    return OK;
}

/* read_image_data()
 * Reads binary data from a file descriptor into a dynamically allocated buffer
 *
 * inFD: The input file descriptor to read
 * data: A pointer to a pointer to unsigned char which will point to the
 * dynamically allocated buffer containing the read data
 * length: A pointer to the size_t variable where total length of read data is
 * stored
 *
 * returns: integer status 0 if data is successfully read or non zero if no data
 * is read
 */
int read_image_data(int inFD, unsigned char** data, size_t* length)
{
    int fd = STDIN_FILENO; // Default to stdin
    if (inFD != -1) { // If it's not -1 an input file was defined
        fd = inFD;
    }
    unsigned char buffer[BUFFER_SIZE]; // unsigned char for raw binary data
    ssize_t bytesRead; // Use ssize_t because read < 0 if there is failure
    // initialise pointers
    *data = NULL;
    *length = 0;
    // Read data until there is no more to read
    while ((bytesRead = read(fd, buffer, BUFFER_SIZE)) > 0) {
        // Dynamically reallocate memory to accommodate newly read data
        unsigned char* newData = realloc(*data, *length + bytesRead);
        *data = newData; // update pointer to point to newly allocated memory
        // Copy newly read data from buffer to allocated memory
        memcpy(*data + *length, buffer, bytesRead);
        *length += bytesRead; // update total length of data read
    }
    // Check if no data read
    if (*length == 0) {
        fprintf(stderr, "uqimageclient: no data read for input image\n");
        return NO_IMAGE_DATA;
    }
    return OK;
}

/* create_request_path()
 * Converts the input program parameters into a request to be used for the
 * server.
 *
 * params: A structure containing input program parameters
 *
 * returns: A dynamically allocated request
 */
char* create_request_path(const ProgParams params)
{
    // sprintf to store string in buffer
    char* path = malloc(BUFFER_SIZE);
    strcpy(path, "/"); // initiaise with '/'
    int operationsAdded = 0; // keep track of operations added to path
    if (params.rotate != 0) {
        // go to end of path array and add rotate
        sprintf(path + strlen(path), "rotate,%d/", params.rotate);
        operationsAdded++;
    }
    if (params.width != 0 && params.height != 0) {
        sprintf(path + strlen(path), "scale,%d,%d/", params.width,
                params.height);
        operationsAdded++;
    }
    if (params.orientation != '\0') {
        sprintf(path + strlen(path), "flip,%c/", params.orientation);
        operationsAdded++;
    }

    // Use default if no operations added
    if (operationsAdded == 0) {
        sprintf(path + strlen(path), "rotate,0/");
    }
    path[strlen(path) - 1] = '\0'; // remove last '/'
    return path;
}

/* send_http_request()
 * Sends a HTTP POST request with image data over specified socket
 *
 * socketFD: The file descriptor of the socket used
 * path: the generated command request for the server
 * imageData: A pointer to the binary image data to be sent
 * imageDataSize: The size of the image data in bytes
 *
 * returns: Integer status 0 if both the header and image data are successfully
 * sent otherwise non zero
 */
int send_http_request(int socketFD, char* path, unsigned char* imageData,
        size_t imageDataSize)
{
    char header[BUFFER_SIZE];
    // Create HTTP request header
    int headerLen = snprintf(header, sizeof(header),
            "POST %s HTTP/1.1\r\n" // Carriage return followed by line feed
            "Host: localhost\r\n"
            "Content-Type: application/octet-stream\r\n" // Set as binary data
            "Content-Length: %zu\r\n" // Provide length of content
            "\r\n",
            path, imageDataSize);
    // Send the http request header over socket
    if (write(socketFD, header, headerLen) < 0) {
        return NO_RESPONSE;
    }

    // Send image data
    if (write(socketFD, imageData, imageDataSize) < 0) {
        return NO_RESPONSE;
    }
    return OK;
}

/* no_http_response()
 * Outputs an error message and exits if the server connection was closed
 */
void no_http_response()
{
    fprintf(stderr, "uqimageclient: server connection closed\n");
    exit(NO_RESPONSE);
}

/**
 * Reads HTTP response from a socket and writes the content to a specified
 * output descriptor
 *
 * socketFD: the file descriptor of the socket to read from
 * outFD: The file descriptor for the output file which will default to stdout
 * if it is -1
 *
 * returns: Integer status 0 if function perfomed correctly
 */
int read_http_response(int socketFD, int outFD)
{
    // Convert FD to FILE* for read
    FILE* inStream = fdopen(socketFD, "r");
    // As per man page
    int status;
    char* statusExplanation;
    unsigned char* body;
    unsigned long bodySize;
    HttpHeader** headers;
    int result = OK;

    if (get_HTTP_response(inStream, &status, &statusExplanation, &headers,
                &body, &bodySize)) {

        if (status == HTTP_OK_STATUS && bodySize > 0) {
            FILE* outStream;
            if (outFD == -1) { // output file not specified
                outStream = stdout;
            } else {
                outStream = fdopen(outFD, "w");
            }
            if (fwrite(body, 1, bodySize, outStream) != bodySize) {
                fprintf(stderr, "uqimageclient: error while writing output\n");
                result = WRITE_RESPONSE_ERROR;
            }
            // Close outputfile if its not stdout
            if (outFD != -1) {
                fclose(outStream);
            }

        } else {
            // Handle non-OK responses by printing body to stderr
            //".*" preceding s indicates maximum number of characters to be
            //  printed from string since it isn't guaranteed to be null
            //  terminated i.e., binary data
            fprintf(stderr, "%.*s", (int)bodySize, body);
            result = NOT_OK_RESPONSE;
        }
        free(statusExplanation);
        free(body);
        free(headers);
    } else {
        result = NO_RESPONSE;
    }
    fclose(inStream); // close input stream
    return result;
}

/* port_error()
 * Outputs and error message and exits if there was a problem establishing
 * a connection to the specified port
 *
 * port: The specifed port
 */
void port_error(const char* port)
{
    fprintf(stderr,
            "uqimageclient: unable to establish connection to port "
            "\"%s\"\n",
            port);
    exit(PORT_ERROR);
}

/* free_memory ()
 * Frees the dynamically allocated memory used by the program
 *
 * imageData: The buffer containing binary image data
 * fileFDs: the struct containing the fileFDs
 * socketFD: The file descriptor for the socket used for communication
 * path: the array storing the address generated from commandline arguments
 */
void free_memory(
        unsigned char* imageData, FileInfo fileFDs, int socketFD, char* path)
{
    free(imageData);
    close(fileFDs.outFD);
    close(socketFD);
    free(path);
}

int main(int argc, char** argv)
{
    ProgParams params = process_cmds(argc, argv); // parse cmdline args
    // try opening provided files
    FileInfo fileFDs = verify_files(params.inFile, params.outFile);
    sigpipe_handler(); // Setup signal handling to ignore SIGPIPE
    int socketFD;
    int portCheck = verify_port(params.port, &socketFD);
    if (portCheck != OK) {
        free_memory(NULL, fileFDs, socketFD, NULL);
        port_error(params.port);
    }
    unsigned char* imageData = NULL; // Buffer for imageData
    size_t imageDataSize = 0;
    int readResult = read_image_data(fileFDs.inFD, &imageData, &imageDataSize);
    if (readResult != OK) { // Handle read failure
        free_memory(imageData, fileFDs, socketFD, NULL);
        exit(readResult);
    }

    char* path = create_request_path(params); // create address
    int sendStatus
            = send_http_request(socketFD, path, imageData, imageDataSize);
    ;
    if (sendStatus != OK) { // Handle HTTP request failure
        free_memory(imageData, fileFDs, socketFD, path);
        no_http_response();
    }
    int result = read_http_response(socketFD, fileFDs.outFD);
    free_memory(imageData, fileFDs, socketFD, path);
    if (result == NO_RESPONSE) { // Handle response failure
        no_http_response();
    } else if (result != 0) {
        exit(result);
    }
    return OK;
}
