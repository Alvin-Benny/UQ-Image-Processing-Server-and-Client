/* uqimageproc.c
 *
 * Written by Alvin Benny
 *
 * uqimageproc is a networked, multithreaded, image processing server. It
 * allows multiple, simultaneously connected clients to send images for
 * manipulation and then receive processed images back. All communication
 * between clients and the server is via HTTP over TCP.
 */
#include <FreeImage.h>
#include <csse2310_freeimage.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <ctype.h>
#include <pthread.h>
#include <signal.h>
#include <semaphore.h>
#include <csse2310a4.h>

#define HOMEPAGE_FILEPATH "/local/courses/csse2310/resources/a4/home.html"
#define BUFFER_SIZE 1024

// Program Parameters
typedef struct {
    char* portNum;
    int maxClients;
} ProgParams;

// Struct to store server statistics
typedef struct {
    unsigned int currentClients;
    unsigned int totalClients;
    unsigned int successfulRequests;
    unsigned int httpErrors;
    unsigned int imageOperations;
    pthread_mutex_t mutex;
} Stats;

// Struct to pass items to threads
typedef struct {
    int serverSocket;
    sem_t* semaphore;
    Stats* stats;
} ClientData;

// Command line option arguments
const char* const portNumArg = "--listenOn";
const char* const maxClientsArg = "--maxClients";

// Exit codes
typedef enum {
    USAGE_ERROR = 14,
    OK = 0,
    PORT_ERROR = 18,
    ROTATE_ERROR = 501,
    FLIP_ERROR = 502,
    SCALE_ERROR = 503,
    INVALID_ADDRESS = -2
} ExitStatus;

// Specified constraints
typedef enum {
    MAX_CLIENTS = 10000,
    ROTATE_MIN = -359,
    ROTATE_MAX = 359,
    MAX_BODY_SIZE = 8388608,
    SCALE_ARG_COUNT = 3,
    BACKLOG = 10
} Constraints;

// Struct for image parameters
typedef struct {
    int rotate;
    int width;
    int height;
    char orientation;
} ImageParams;

/* usage_error()
 * Outputs an usage error message if invalid parameters are passed when starting
 * the server.
 */
void usage_error()
{
    fprintf(stderr,
            "Usage: uqimageproc [--listenOn portnum] [--maxClients num]\n");
    exit(USAGE_ERROR);
}

/* sigpipe_handler()
 * setups signal handler to ignore SIGPIPE so server doesn't exit when receiving
 * this signal.
 */
void sigpipe_handler()
{
    struct sigaction sa; // struct to hold signal settings
    sa.sa_handler = SIG_IGN; // Set handler to ignore signal
    sa.sa_flags = 0; // Prevent special behaviour i.e., automatic restart
    // Use NULL to discard previous action settings for SIGPIPE
    sigaction(SIGPIPE, &sa, NULL); // Apply confirguation to SIGPIPE
}

/* mask_signals()
 * Block SIGHUP in all threads by default
 */
void mask_signals()
{
    // REF: Code inspired by:
    // REF: https://stackoverflow.com/questions/54871085/is-it-a-good-practice-
    // to-call-pthread-sigmask-in-a-thread-created-by-stdthread
    sigset_t set; // Declare set of signals
    sigemptyset(&set); // Initialise signal set to be empty
    sigaddset(&set, SIGHUP); // Add SIGHUP to the signal set
    pthread_sigmask(SIG_BLOCK, &set, NULL); // Block SIGHUP signals
}

/* initialise_semaphore()
 * Creates semaphore to keep track of the number of connected clients
 *
 * maxClients: The user specified maximum number of clients which defaults to
 * the MAX_CLIENTS arg.
 * connectionLimiter: the semaphore variable used.
 */
void initialise_semaphore(int maxClients, sem_t* connectionLimiter)
{
    // sem_t* connectionLimiter acts as a counter controlling the number of
    // threads
    // 0 indicates semaphore is shared between threads of the same process
    // maxClients sets the initial value of the semaphore (how many clients can
    // be simultaneously handled)
    sem_init(connectionLimiter, 0, maxClients);
}

/* handle_prefix()
 * Removes leading plus sign from a numeric string if present.
 *
 * arg: A pointer to the string that may begin with a plus sign.
 *
 * returns: A pointer to the string incremented by 1 if the plus sign was
 * present else just the original pointer.
 */
char* handle_prefix(char* arg)
{
    if (arg[0] == '+') {
        arg = arg + 1;
    }
    return arg;
}

/* process_cmds()
 * Parses and verifies the input command line arguments.
 *
 * argc: Variable storing the number of command line arguments
 * argv: An array containing the command line arguments.
 *
 * returns: A struct containing the parsed command line arguments.
 */

ProgParams process_cmds(int argc, char* argv[])
{
    ProgParams params = {NULL, 0};
    for (int i = 1; i < argc; i++) {
        // If portNum is specified, check if following arg exists
        // and portNum hasn't been specified before
        if (strcmp(argv[i], portNumArg) == 0 && i + 1 < argc
                && strlen(argv[i + 1]) > 0 && !params.portNum) {
            params.portNum = argv[++i];
        } else if (strcmp(argv[i], maxClientsArg) == 0 && i + 1 < argc
                && !params.maxClients) {
            char* nextArg = argv[++i];
            // skip the leading plus if present
            nextArg = handle_prefix(nextArg);
            // Convert to integer
            params.maxClients = atoi(nextArg);
            // If it's negative, greater than max, or equal to 0 (atoi failed)
            // then usage error
            if (params.maxClients < 0 || params.maxClients > MAX_CLIENTS
                    || params.maxClients == 0) {
                usage_error();
            }
        } else {
            // Unexpected argument
            usage_error();
        }
    }
    if (!params.portNum) {
        params.portNum = "0";
    }
    return params;
}

/* port_error(port)
 * Called to output an error message when the provided port cannot be used.
 *
 * port: the provided port.
 */
void port_error(char* port)
{
    fprintf(stderr, "uqimageproc: cannot listen on port \"%s\"\n", port);
    exit(PORT_ERROR);
}

/** read_home_page()
 * Opens and stores the provided home page file into a buffer and returns it.
 *
 * returns: A buffer containing the read home page file.
 */
char* read_home_page()
{
    char* data = NULL;
    size_t length = 0;
    char buffer[BUFFER_SIZE];
    size_t bytesRead;
    FILE* file = fopen(HOMEPAGE_FILEPATH, "r");
    if (!file) {
        return NULL;
    }

    while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
        char* newData = realloc(data, length + bytesRead + 1);
        data = newData;
        memcpy(data + length, buffer, bytesRead);
        length += bytesRead;
    }
    data[length] = '\0';
    fclose(file);
    return data;
}

// Based on server-multithreaded.c
/* open_listen()
 * Confirgures a server socket and binds it to the specified port to listen for
 * incoming connections. If a port is not provided, an ephemeral port is
 * generated. The port is printed to stderr.
 *
 * port: The provided port.
 * returns: The file descriptor for the listening socket. -1 if error occurs
 */
int open_listen(const char* port)
{
    struct addrinfo* ai = 0;
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // listen on all IP addresses

    int err;
    if ((err = getaddrinfo(NULL, port, &hints, &ai))) {
        return -1;
    }

    // Create a socket and bind it to a port
    int socketFD = socket(AF_INET, SOCK_STREAM, 0); // 0=default protocol (TCP)
    // Allow address(port number) to be reused immediately
    int optVal = 1;
    if (setsockopt(socketFD, SOL_SOCKET, SO_REUSEADDR, &optVal, sizeof(int))
            < 0) {
        freeaddrinfo(ai);
        return -1;
    }

    if (bind(socketFD, ai->ai_addr, sizeof(struct sockaddr)) < 0) {
        freeaddrinfo(ai);
        return -1;
    }

    // Which port did we get? (week 9 net4.c)
    struct sockaddr_in ad;
    memset(&ad, 0, sizeof(struct sockaddr_in));
    socklen_t len = sizeof(struct sockaddr_in);
    if (getsockname(socketFD, (struct sockaddr*)&ad, &len)) {
        freeaddrinfo(ai);
        return -1;
    }
    fprintf(stderr, "%u\n", ntohs(ad.sin_port));
    fflush(stderr);

    // BACKLOG for maximum number of incoming connections
    if (listen(socketFD, BACKLOG) < 0) {
        freeaddrinfo(ai);
        return -1;
    }
    // Return listening socket
    freeaddrinfo(ai);
    return socketFD;
}

/* handle_rotate()
 * Rotates the image by the provided angle.
 *
 * bitmap: The image bitmap
 * angle: the angle to rotate the image.
 *
 * returns: Integer status OK (0) if successful, otherwise a respective error
 * code.
 */
int handle_rotate(FIBITMAP** bitmap, int angle)
{
    *bitmap = FreeImage_Rotate(*bitmap, (double)angle, NULL);
    if (!*bitmap) {
        return ROTATE_ERROR;
    }
    return OK;
}

/* handle_flip()
 * Flips an image by the provided direction.
 *
 * bitmap: The image bitmap.
 * direction: The direction which specifies over which axis to flip the image.
 *
 * returns: Integer status OK (0) if successful, otherwise a respective error
 * code.
 */
int handle_flip(FIBITMAP** bitmap, char direction)
{
    if (direction == 'h') {
        if (!FreeImage_FlipHorizontal(*bitmap)) {
            return FLIP_ERROR;
        }
    } else {
        if (!FreeImage_FlipVertical(*bitmap)) {
            return FLIP_ERROR;
        }
    }
    return OK;
}

/* handle_scale()
 * Scales the provided image by a provided width and height.
 *
 * bitmap: The image bitmap.
 * width: The width to scale.
 * height: The height to scale.
 *
 * returns: Integer status OK (0) if successful, otherwise a respective error
 * code.
 */
int handle_scale(FIBITMAP** bitmap, int width, int height)
{
    *bitmap = FreeImage_Rescale(*bitmap, width, height, FILTER_BILINEAR);
    if (!*bitmap) {
        return SCALE_ERROR;
    }
    return OK;
}

/* fill_response()
 * Completes the final parts of a HTTP response based on input parameters.
 *
 * contentLength: The length of the responseBody being sent.
 * clientStream: The FILE* variable based on the communciation socket.
 * responsebody: The response being sent.
 */
void fill_response(unsigned long contentLength, FILE* clientStream,
        const char* responseBody)
{
    fprintf(clientStream, "Content-Type: text/plain\r\n");
    fprintf(clientStream, "Content-Length: %lu\r\n\r\n", contentLength);
    fwrite(responseBody, sizeof(char), contentLength, clientStream);
    fflush(clientStream);
}

/** process_operation()
 * Verifies and performs the given commad to the image
 *
 * operationPart: The command to be performed
 * bitmap: The bitmap of the image to be manipulated
 *
 * returns integer status OK (0) if successful, nonzero otherwise
 */
int process_operation(char* operationPart, FIBITMAP** bitmap)
{
    int result = OK;
    char** operationDetails = split_by_char(operationPart, ',', 0);
    if (!operationDetails) {
        return INVALID_ADDRESS;
    }
    int numArgs = 0;
    while (operationDetails[numArgs] != NULL) {
        numArgs++; // Count args for this operation
    }
    const char* operationName = operationDetails[0];
    if (strcmp(operationName, "rotate") == 0 && numArgs == 2) {
        char* input = handle_prefix(operationDetails[1]);
        int angle = atoi(input);
        if ((strcmp(input, "0") != 0 && angle == 0) || angle < ROTATE_MIN
                || angle > ROTATE_MAX) { // if atoi fails or angle not valid
            result = INVALID_ADDRESS;
        } else {
            result = handle_rotate(bitmap, angle);
        }
    } else if (strcmp(operationName, "flip") == 0 && numArgs == 2
            && (operationDetails[1][0] == 'h'
                    || operationDetails[1][0] == 'v')) {
        // can only be 'h'' or 'v'
        result = handle_flip(bitmap, operationDetails[1][0]);
    } else if (strcmp(operationName, "scale") == 0
            && numArgs == SCALE_ARG_COUNT) {
        int width = atoi(handle_prefix(operationDetails[1]));
        int height = atoi(handle_prefix(operationDetails[2]));
        if (width > 0 && height > 0) { // must be positive
            result = handle_scale(bitmap, width, height);
        } else {
            result = INVALID_ADDRESS;
        }
    } else {
        result = INVALID_ADDRESS;
    }
    free(operationDetails);
    return result;
}

/* valid_operation()
 * Checks if the provided list of operations are valid and performs them
 *
 * address: The string containing the list of operations.
 * bitmap: The loaded bitmap of the image ready for manipulation.
 *
 * returns: Integer status non zero if unsuccessful (not valid) or zero
 * otherwise.
 */

int valid_operation(char* address, FIBITMAP** bitmap, ClientData* data)
{
    char** operations = split_by_char(address, '/', 0);
    if (!operations) { // Couldn't be split by chars
        return INVALID_ADDRESS;
    }
    int validOp = 0;
    for (int i = 1; operations[i] != NULL && !validOp; i++) {
        validOp = process_operation(operations[i], bitmap);
    }
    if (validOp == 0) {
        pthread_mutex_lock(&data->stats->mutex);
        data->stats->imageOperations++;
        pthread_mutex_unlock(&data->stats->mutex);
    }

    free(operations);
    return validOp;
}

/* send_home_page_response
 * Outputs the home page to the client.
 *
 * clientStream: The stream for the socket.
 */
void send_home_page_response(FILE* clientStream)
{
    char* responseBody = read_home_page();
    if (responseBody == NULL) {
        fprintf(clientStream, "HTTP/1.1 500 Internal Server Error\r\n");
        fprintf(clientStream, "Content-Type: text/html\r\n");
        fprintf(clientStream, "Content-Length: 23\r\n\r\n");
        fprintf(clientStream, "Failed to load homepage.\r\n");
        return;
    }

    unsigned long contentLength = strlen(responseBody);
    // Use \r\n twice to end headers
    fprintf(clientStream, "HTTP/1.1 200 OK\r\n");
    fprintf(clientStream, "Content-Type: text/html\r\n");
    fprintf(clientStream, "Content-Length: %lu\r\n\r\n", contentLength);
    fwrite(responseBody, sizeof(char), contentLength, clientStream);
    free(responseBody);
    fflush(clientStream);
}

/* send_400_response()
 * Outputs to client if the format of the provided operations is invalid.
 *
 * clientStream: The stream for the socket.
 */
void send_400_response(FILE* clientStream)
{
    const char* responseBody = "Invalid image operation\n";
    unsigned long contentLength = strlen(responseBody);
    fprintf(clientStream, "HTTP/1.1 400 Bad Request\r\n");
    fill_response(contentLength, clientStream, responseBody);
}

/* send_404_response()
 * Outputs to the client if the address for GET request is invalid.
 *
 * clientStream: The stream for the socket.
 */
void send_404_response(FILE* clientStream)
{
    const char* responseBody = "Invalid address on request line\n";
    unsigned long contentLength = strlen(responseBody);
    fprintf(clientStream, "HTTP/1.1 404 Not Found\r\n");
    fill_response(contentLength, clientStream, responseBody);
}

/* send_405_response()
 * Outputs to the client if the server receives anything other than a POST or
 * GET request.
 *
 * clientStream: The stream for the socket.
 */
void send_405_response(FILE* clientStream)
{
    const char* responseBody = "Invalid method on request list\n";
    unsigned long contentLength = strlen(responseBody);
    fprintf(clientStream, "HTTP/1.1 405 Method Not Allowed\r\n");
    fill_response(contentLength, clientStream, responseBody);
}

/* send_413_response()
 * Outputs a message to the client if the body of an image manipulation request
 * is too large.
 *
 * clientStream: the stream for the socket.
 */
void send_413_response(FILE* clientStream, unsigned long bodySize)
{
    char responseBody[BUFFER_SIZE];
    snprintf(responseBody, BUFFER_SIZE, "Image too large: %lu bytes\n",
            bodySize);
    unsigned long contentLength = strlen(responseBody);
    fprintf(clientStream, "HTTP/1.1 413 Payload Too Large\r\n");
    fill_response(contentLength, clientStream, responseBody);
}

/* send_422_response()
 * Sends an error message to the client if the provided image cannot be
 * processed i.e., attempt to create bitmap fails.
 *
 * clientStream: the stream for the socket.
 */
void send_422_response(FILE* clientStream)
{
    const char* responseBody = "Invalid image in request\n";
    unsigned long contentLength = strlen(responseBody);
    fprintf(clientStream, "HTTP/1.1 422 Unprocessable Content\r\n");
    fill_response(contentLength, clientStream, responseBody);
}

/* send_501_response()
 * Outputs an error message to the client if any of the image operations fail.
 *
 * clientStream: The stream for the socket.
 * errorCode: the errorCode denoting what operation failed.
 */
void send_501_response(FILE* clientStream, int errorCode)
{
    char* operation = "";
    if (errorCode == ROTATE_ERROR) {
        operation = "rotate";
    } else if (errorCode == FLIP_ERROR) {
        operation = "flip";
    } else if (errorCode == SCALE_ERROR) {
        operation = "scale";
    }
    char responseBody[BUFFER_SIZE];
    snprintf(responseBody, BUFFER_SIZE, "Operation failed: %s\n", operation);
    unsigned long contentLength = strlen(responseBody);
    fprintf(clientStream, "HTTP/1.1 501 Not Implemented\r\n");
    fill_response(contentLength, clientStream, responseBody);
}

/* send_200_response()
 * Outputs the successfuly processed image file to the client.
 *
 * clientStream: The stream for the socket.
 * bitmap: the final bitmap for the image.
 */
void send_200_response(FILE* clientStream, FIBITMAP* bitmap)
{
    unsigned long size = 0;
    unsigned char* finalImage = fi_save_png_image_to_buffer(bitmap, &size);
    fprintf(clientStream, "HTTP/1.1 200 OK\r\n");
    fprintf(clientStream, "Content-Type: image/png\r\n");
    fprintf(clientStream, "Content-Length: %lu\r\n\r\n", size);
    fwrite(finalImage, 1, size, clientStream);
    fflush(clientStream);

    FreeImage_Unload(bitmap);
    free(finalImage);
}

/* reset_request_vars()
 * Resets the variables used to retrieve new requests from the client.
 *
 * method: A pointer to the variable the stores the method of request i.e.,
 * POST, GET.
 * address: A pointer to the variable that stores the list of operations.
 * headers: A pointer to the pointer of the http headers.
 * body: A pointer to the body of the http request.
 * bodySize: A pointer to a variable the stores the size of the body.
 */
void reset_request_vars(char** method, char** address, HttpHeader*** headers,
        unsigned char** body, unsigned long* bodySize)
{
    free(*method);
    free(*address);
    free(*body);
    free_array_of_headers(*headers);
    *method = NULL;
    *address = NULL;
    *headers = NULL;
    *body = NULL;
    *bodySize = 0;
}

/* handle_post_request()
 * Attempts to handle a POST request by loading and applying operations to the
 * bitmap.
 *
 * clientStream: The stream for the socket.
 * address: the list of operations.
 * body: The body of the request containing the image data.
 * bodySize: A variable the stores the size of the body.
 */
void handle_post_request(FILE* clientStream, char* address, unsigned char* body,
        unsigned long bodySize, ClientData* data)
{
    if (bodySize > MAX_BODY_SIZE) {
        send_413_response(clientStream, bodySize);
        return;
    }
    FIBITMAP* bitmap = fi_load_image_from_buffer(body, bodySize);
    // Have to clone for test 18.5 and meet requirements of spec (work in prog)
    FIBITMAP* clone = fi_load_image_from_buffer(body, bodySize);
    int opResult = valid_operation(address, &bitmap, data);

    if (opResult == INVALID_ADDRESS) {
        send_400_response(clientStream);
        pthread_mutex_lock(&data->stats->mutex);
        data->stats->httpErrors++;
        pthread_mutex_unlock(&data->stats->mutex);
        FreeImage_Unload(bitmap);
        FreeImage_Unload(clone);

    } else if (clone == NULL) {
        send_422_response(clientStream);
        pthread_mutex_lock(&data->stats->mutex);
        data->stats->httpErrors++;
        pthread_mutex_unlock(&data->stats->mutex);
        return;
    }

    else if (opResult != OK) {
        send_501_response(clientStream, opResult);
        pthread_mutex_lock(&data->stats->mutex);
        data->stats->httpErrors++;
        pthread_mutex_unlock(&data->stats->mutex);
        FreeImage_Unload(bitmap);
        FreeImage_Unload(clone);
    } else {
        FreeImage_Unload(clone);
        send_200_response(clientStream, bitmap);
        pthread_mutex_lock(&data->stats->mutex);
        data->stats->successfulRequests++;
        pthread_mutex_unlock(&data->stats->mutex);
    }
}

/* handle_get_request()
 * Verifies the validity of a GET request and calls helper methods to try
 * and output the home page.
 *
 * clientStream: The stream for the socket.
 * address: The address of the GET request.I
 * data: Struct containing the pointer to the statistics struct
 */
void handle_get_request(FILE* clientStream, char* address, ClientData* data)
{
    if (strcmp(address, "/") == 0) { // root address '/'
        send_home_page_response(clientStream);
        pthread_mutex_lock(&data->stats->mutex);
        data->stats->successfulRequests++;
        pthread_mutex_unlock(&data->stats->mutex);
    } else {
        send_404_response(clientStream);
    }
}

/* client_thread()
 * Manages the newly created thread for each client and processes HTTP requests.
 *
 * arg: A struct containing information for the socket file descriptor and
 * semaphore variable as well as access to the statistics struct.
 * return: NULL after completing execution
 */
void* client_thread(void* arg)
{
    ClientData* data = (ClientData*)arg;
    pthread_mutex_lock(&data->stats->mutex);
    data->stats->currentClients++;
    pthread_mutex_unlock(&data->stats->mutex);

    int clientSock = data->serverSocket;
    sem_t* semaphore = data->semaphore;
    int sockDup = dup(clientSock); // So we are not reading/writing same stream
    // Convert to FILE* for reading/writing
    FILE* readStream = fdopen(clientSock, "r");
    FILE* clientStream = fdopen(sockDup, "w");
    char* method = NULL;
    char* address = NULL;
    HttpHeader** headers = NULL;
    unsigned char* body = NULL;
    unsigned long bodySize = 0;
    // Keep processing HTTP requests until connection should close
    while (1) {
        if (!get_HTTP_request(readStream, &method, &address, &headers, &body,
                    &bodySize)) {
            break;
        }
        if (method) {
            if (strcmp(method, "POST") == 0) {
                handle_post_request(
                        clientStream, address, body, bodySize, data);
            } else if (strcmp(method, "GET") == 0) {
                handle_get_request(clientStream, address, data);
            } else {
                send_405_response(clientStream);
            }
        }
    }
    reset_request_vars(&method, &address, &headers, &body, &bodySize);
    fclose(readStream);
    fclose(clientStream);
    close(sockDup);
    free(data);
    sem_post(semaphore); // Increment count for semaphore
    pthread_mutex_lock(&data->stats->mutex);
    data->stats->currentClients--;
    data->stats->totalClients++;
    pthread_mutex_unlock(&data->stats->mutex);
    pthread_exit(NULL);
}

/* process_connections()
 * Sets server to repeatedly accept incoming connections requests on the
 * provided socket. For each accepted connection, it creates a create unique
 * thread to handle client requests. It uses a semaphore to control the number
 * of concurrent client connections.
 *
 * data: A struct containing the semaphore variable, socket, and Stats struct.
 * file descriptor as well as access to a statistics struct.
 */
void process_connections(ClientData* data, Stats* stats)
{
    int fd;
    struct sockaddr_in fromAddr;
    socklen_t fromAddrSize;
    // Repeatedly accept connections and process data
    while (1) {
        // will block if semaphore is 0 else decrement the count and proceed
        sem_wait(data->semaphore);
        fromAddrSize = sizeof(struct sockaddr_in);
        // Block waiting for new connection (fromAddr will be populated with
        // address of client)
        fd = accept(
                data->serverSocket, (struct sockaddr*)&fromAddr, &fromAddrSize);
        if (fd < 0) {
            perror("Error accepting connection");
            sem_post(data->semaphore); // release if accept fails
            continue; // Continue accepting without shutting down
        }

        // Turn client address into hostname and print out both address and
        // hostname as well as port number
        char hostname[NI_MAXHOST];
        int error = getnameinfo((struct sockaddr*)&fromAddr, fromAddrSize,
                hostname, NI_MAXHOST, NULL, 0, 0);
        if (error) {
            fprintf(stderr, "Error getting hostname: %s\n",
                    gai_strerror(error));
        } else {
            printf("Accepted connection from %s (%s), port %d\n",
                    inet_ntoa(fromAddr.sin_addr), hostname,
                    ntohs(fromAddr.sin_port));
        }
        // Create unique copy of data for each thread and avoid race conditons
        ClientData* clientData = malloc(sizeof(ClientData));
        clientData->serverSocket = fd;
        clientData->semaphore = data->semaphore;
        clientData->stats = stats;

        pthread_t threadID;
        // NULL for default thread attribtues i.e., stack size
        pthread_create(&threadID, NULL, client_thread, clientData);
        pthread_detach(threadID);
    }
}

/* Creates a thread continuously waiting for  a SIGHUP signal. Upon receiving
 * SIGHUP it outputs the statistics of the server to stderr
 *
 * arg: A pointer to the Stats struct where the statistics are stored
 */
void* signal_handler(void* arg)
{
    // REF: Code inspired by the code at:
    // REF: https://stackoverflow.com/questions/72812375/use-sigwait-to-block-a
    // REF: -specific-signal-without-blocking-sigint
    sigset_t set; // Define set of signals to be handled
    int sig; // Variable to store the signal number that was received
    Stats* stats = (Stats*)arg; // Cast argument to Stats pointer to access

    // Initialise the signal set and add SIGHUP to the set
    sigemptyset(&set);
    sigaddset(&set, SIGHUP);

    while (1) {
        sigwait(&set, &sig); // Wait for any signal
        if (sig == SIGHUP) { // if a signal received is SIGHUP
            pthread_mutex_lock(&stats->mutex); // safely access shared data
            fprintf(stderr, "Currently connected clients: %u\n",
                    stats->currentClients);
            fprintf(stderr, "Num completed clients: %u\n", stats->totalClients);
            fprintf(stderr, "Successful HTTP requests: %u\n",
                    stats->successfulRequests);
            fprintf(stderr, "HTTP error responses: %u\n", stats->httpErrors);
            fprintf(stderr, "Operations on images: %u\n",
                    stats->imageOperations);
            pthread_mutex_unlock(&stats->mutex);
        }
    }
}

int main(int argc, char* argv[])
{
    sigpipe_handler(); // Setup signal handling to ignore SIGPIPE
    pthread_t tid;
    // Setup serverStats struct including mutex
    Stats serverStats = {0, 0, 0, 0, 0, PTHREAD_MUTEX_INITIALIZER};
    pthread_mutex_init(&serverStats.mutex, NULL);
    ProgParams params = process_cmds(argc, argv);
    mask_signals(); // Setup all threads to block SIGUP by default
    // Create signal handling thread
    pthread_create(&tid, NULL, signal_handler, (void*)&serverStats);
    pthread_detach(tid);

    // Set the semaphore based on whether maxClients was specified else
    // use default
    sem_t connectionLimiter;
    if (params.maxClients != 0) {
        initialise_semaphore(params.maxClients, &connectionLimiter);
    } else {
        initialise_semaphore(MAX_CLIENTS, &connectionLimiter);
    }

    // Try and create a socket based on the provided port
    int socketFD = open_listen(params.portNum);
    if (socketFD == -1) {
        port_error(params.portNum);
    }
    // Setup data for client connections
    ClientData data = {socketFD, &connectionLimiter, &serverStats};
    process_connections(&data, &serverStats); // Begin listening and processing
    // clean up
    sem_destroy(&connectionLimiter);
    close(socketFD);
    return OK;
}
