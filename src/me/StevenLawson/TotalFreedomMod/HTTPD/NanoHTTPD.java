package me.StevenLawson.TotalFreedomMod.HTTPD;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.text.SimpleDateFormat;
import java.util.*;
import me.StevenLawson.TotalFreedomMod.TFM_Log;

public abstract class NanoHTTPD
{
    public static final String MIME_PLAINTEXT = "text/plain";
    public static final String MIME_HTML = "text/html";
    public static final String MIME_JSON = "application/json";
    private static final String QUERY_STRING_PARAMETER = "NanoHttpd.QUERY_STRING";
    private final String hostname;
    private final int myPort;
    private ServerSocket myServerSocket;
    private Thread myThread;
    private AsyncRunner asyncRunner;
    private TempFileManagerFactory tempFileManagerFactory;

    public NanoHTTPD(int port)
    {
        this(null, port);
    }

    public NanoHTTPD(String hostname, int port)
    {
        this.hostname = hostname;
        this.myPort = port;
        setTempFileManagerFactory(new DefaultTempFileManagerFactory());
        setAsyncRunner(new DefaultAsyncRunner());
    }

    private static final void safeClose(ServerSocket serverSocket)
    {
        if (serverSocket != null)
        {
            try
            {
                serverSocket.close();
            }
            catch (IOException e)
            {
            }
        }
    }

    private static final void safeClose(Socket socket)
    {
        if (socket != null)
        {
            try
            {
                socket.close();
            }
            catch (IOException e)
            {
            }
        }
    }

    private static final void safeClose(Closeable closeable)
    {
        if (closeable != null)
        {
            try
            {
                closeable.close();
            }
            catch (IOException e)
            {
            }
        }
    }

    public void start() throws IOException
    {
        myServerSocket = new ServerSocket();
        myServerSocket.bind((hostname != null) ? new InetSocketAddress(hostname, myPort) : new InetSocketAddress(myPort));

        myThread = new Thread(new Runnable()
        {
            @Override
            public void run()
            {
                do
                {
                    try
                    {
                        final Socket finalAccept = myServerSocket.accept();
                        final InputStream inputStream = finalAccept.getInputStream();
                        if (inputStream == null)
                        {
                            safeClose(finalAccept);
                        }
                        else
                        {
                            asyncRunner.exec(new Runnable()
                            {
                                @Override
                                public void run()
                                {
                                    OutputStream outputStream = null;
                                    try
                                    {
                                        outputStream = finalAccept.getOutputStream();
                                        TempFileManager tempFileManager = tempFileManagerFactory.create();
                                        HTTPSession session = new HTTPSession(tempFileManager, inputStream, outputStream, finalAccept);
                                        while (!finalAccept.isClosed())
                                        {
                                            session.execute();
                                        }
                                    }
                                    catch (Exception e)
                                    {
                                        if (!(e instanceof SocketException && "NanoHttpd Shutdown".equals(e.getMessage())))
                                        {
                                            TFM_Log.severe(e);
                                        }
                                    }
                                    finally
                                    {
                                        safeClose(outputStream);
                                        safeClose(inputStream);
                                        safeClose(finalAccept);
                                    }
                                }
                            });
                        }
                    }
                    catch (IOException e)
                    {
                    }
                }
                while (!myServerSocket.isClosed());
            }
        });
        myThread.setDaemon(true);
        myThread.setName("NanoHttpd Main Listener");
        myThread.start();
    }

    public void stop()
    {
        try
        {
            safeClose(myServerSocket);
            myThread.join();
        }
        catch (Exception e)
        {
            TFM_Log.severe(e);
        }
    }

    public final int getListeningPort()
    {
        return myServerSocket == null ? -1 : myServerSocket.getLocalPort();
    }

    public final boolean wasStarted()
    {
        return myServerSocket != null && myThread != null;
    }

    public final boolean isAlive()
    {
        return wasStarted() && !myServerSocket.isClosed() && myThread.isAlive();
    }

    @Deprecated
    public Response serve(String uri, Method method, Map<String, String> headers, Map<String, String> parms,
            Map<String, String> files)
    {
        return new Response(Response.Status.NOT_FOUND, MIME_PLAINTEXT, "Not Found");
    }

    public Response serve(HTTPSession session)
    {
        Map<String, String> files = new HashMap<String, String>();
        Method method = session.getMethod();
        if (Method.PUT.equals(method) || Method.POST.equals(method))
        {
            try
            {
                session.parseBody(files);
            }
            catch (IOException ioe)
            {
                return new Response(Response.Status.INTERNAL_ERROR, MIME_PLAINTEXT, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage());
            }
            catch (ResponseException re)
            {
                return new Response(re.getStatus(), MIME_PLAINTEXT, re.getMessage());
            }
        }

        return serve(session.getUri(), method, session.getHeaders(), session.getParms(), files);
    }

    protected String decodePercent(String str)
    {
        String decoded = null;
        try
        {
            decoded = URLDecoder.decode(str, "UTF8");
        }
        catch (UnsupportedEncodingException ignored)
        {
        }
        return decoded;
    }

    protected Map<String, List<String>> decodeParameters(Map<String, String> parms)
    {
        return this.decodeParameters(parms.get(QUERY_STRING_PARAMETER));
    }

    protected Map<String, List<String>> decodeParameters(String queryString)
    {
        Map<String, List<String>> parms = new HashMap<String, List<String>>();
        if (queryString != null)
        {
            StringTokenizer st = new StringTokenizer(queryString, "&");
            while (st.hasMoreTokens())
            {
                String e = st.nextToken();
                int sep = e.indexOf('=');
                String propertyName = (sep >= 0) ? decodePercent(e.substring(0, sep)).trim() : decodePercent(e).trim();
                if (!parms.containsKey(propertyName))
                {
                    parms.put(propertyName, new ArrayList<String>());
                }
                String propertyValue = (sep >= 0) ? decodePercent(e.substring(sep + 1)) : null;
                if (propertyValue != null)
                {
                    parms.get(propertyName).add(propertyValue);
                }
            }
        }
        return parms;
    }

    public void setAsyncRunner(AsyncRunner asyncRunner)
    {
        this.asyncRunner = asyncRunner;
    }

    public void setTempFileManagerFactory(TempFileManagerFactory tempFileManagerFactory)
    {
        this.tempFileManagerFactory = tempFileManagerFactory;
    }

    public enum Method
    {
        GET, PUT, POST, DELETE, HEAD;

        static Method lookup(String method)
        {
            for (Method m : Method.values())
            {
                if (m.toString().equalsIgnoreCase(method))
                {
                    return m;
                }
            }
            return null;
        }
    }

    public interface AsyncRunner
    {
        void exec(Runnable code);
    }

    public interface TempFileManagerFactory
    {
        TempFileManager create();
    }

    public interface TempFileManager
    {
        TempFile createTempFile() throws Exception;

        void clear();
    }

    public interface TempFile
    {
        OutputStream open() throws Exception;

        void delete() throws Exception;

        String getName();
    }

    public static class DefaultAsyncRunner implements AsyncRunner
    {
        private long requestCount;

        @Override
        public void exec(Runnable code)
        {
            ++requestCount;
            Thread t = new Thread(code);
            t.setDaemon(true);
            t.setName("NanoHttpd Request Processor (#" + requestCount + ")");
            t.start();
        }
    }

    public static class DefaultTempFileManager implements TempFileManager
    {
        private final String tmpdir;
        private final List<TempFile> tempFiles;

        public DefaultTempFileManager()
        {
            tmpdir = System.getProperty("java.io.tmpdir");
            tempFiles = new ArrayList<TempFile>();
        }

        @Override
        public TempFile createTempFile() throws Exception
        {
            DefaultTempFile tempFile = new DefaultTempFile(tmpdir);
            tempFiles.add(tempFile);
            return tempFile;
        }

        @Override
        public void clear()
        {
            for (TempFile file : tempFiles)
            {
                try
                {
                    file.delete();
                }
                catch (Exception ignored)
                {
                }
            }
            tempFiles.clear();
        }
    }

    public static class DefaultTempFile implements TempFile
    {
        private File file;
        private OutputStream fstream;

        public DefaultTempFile(String tempdir) throws IOException
        {
            file = File.createTempFile("NanoHTTPD-", "", new File(tempdir));
            fstream = new FileOutputStream(file);
        }

        @Override
        public OutputStream open() throws Exception
        {
            return fstream;
        }

        @Override
        public void delete() throws Exception
        {
            safeClose(fstream);
            file.delete();
        }

        @Override
        public String getName()
        {
            return file.getAbsolutePath();
        }
    }

    public static class Response
    {
        private Status status;
        private String mimeType;
        private InputStream data;
        private Map<String, String> header = new HashMap<String, String>();
        private Method requestMethod;
        private boolean chunkedTransfer;

        public Response(String msg)
        {
            this(Status.OK, MIME_HTML, msg);
        }

        public Response(Status status, String mimeType, InputStream data)
        {
            this.status = status;
            this.mimeType = mimeType;
            this.data = data;
        }

        public Response(Status status, String mimeType, String txt)
        {
            this.status = status;
            this.mimeType = mimeType;
            try
            {
                this.data = txt != null ? new ByteArrayInputStream(txt.getBytes("UTF-8")) : null;
            }
            catch (java.io.UnsupportedEncodingException uee)
            {
                TFM_Log.severe(uee);
            }
        }

        public void addHeader(String name, String value)
        {
            header.put(name, value);
        }

        private void send(OutputStream outputStream)
        {
            String mime = mimeType;
            SimpleDateFormat gmtFrmt = new SimpleDateFormat("E, d MMM yyyy HH:mm:ss 'GMT'", Locale.US);
            gmtFrmt.setTimeZone(TimeZone.getTimeZone("GMT"));

            try
            {
                if (status == null)
                {
                    throw new Error("sendResponse(): Status can't be null.");
                }
                PrintWriter pw = new PrintWriter(outputStream);
                pw.print("HTTP/1.1 " + status.getDescription() + " \r\n");

                if (mime != null)
                {
                    pw.print("Content-Type: " + mime + "\r\n");
                }

                if (header == null || header.get("Date") == null)
                {
                    pw.print("Date: " + gmtFrmt.format(new Date()) + "\r\n");
                }

                if (header != null)
                {
                    for (String key : header.keySet())
                    {
                        String value = header.get(key);
                        pw.print(key + ": " + value + "\r\n");
                    }
                }

                pw.print("Connection: keep-alive\r\n");

                if (requestMethod != Method.HEAD && chunkedTransfer)
                {
                    sendAsChunked(outputStream, pw);
                }
                else
                {
                    sendAsFixedLength(outputStream, pw);
                }
                outputStream.flush();
                safeClose(data);
            }
            catch (IOException ioe)
            {
            }
        }

        private void sendAsChunked(OutputStream outputStream, PrintWriter pw) throws IOException
        {
            pw.print("Transfer-Encoding: chunked\r\n");
            pw.print("\r\n");
            pw.flush();
            int BUFFER_SIZE = 16 * 1024;
            byte[] CRLF = "\r\n".getBytes();
            byte[] buff = new byte[BUFFER_SIZE];
            int read;
            while ((read = data.read(buff)) > 0)
            {
                outputStream.write(String.format("%x\r\n", read).getBytes());
                outputStream.write(buff, 0, read);
                outputStream.write(CRLF);
            }
            outputStream.write(String.format("0\r\n\r\n").getBytes());
        }

        private void sendAsFixedLength(OutputStream outputStream, PrintWriter pw) throws IOException
        {
            int pending = data != null ? data.available() : 0;
            pw.print("Content-Length: " + pending + "\r\n");

            pw.print("\r\n");
            pw.flush();

            if (requestMethod != Method.HEAD && data != null)
            {
                int BUFFER_SIZE = 16 * 1024;
                byte[] buff = new byte[BUFFER_SIZE];
                while (pending > 0)
                {
                    int read = data.read(buff, 0, ((pending > BUFFER_SIZE) ? BUFFER_SIZE : pending));
                    if (read <= 0)
                    {
                        break;
                    }
                    outputStream.write(buff, 0, read);

                    pending -= read;
                }
            }
        }

        public Status getStatus()
        {
            return status;
        }

        public void setStatus(Status status)
        {
            this.status = status;
        }

        public String getMimeType()
        {
            return mimeType;
        }

        public void setMimeType(String mimeType)
        {
            this.mimeType = mimeType;
        }

        public InputStream getData()
        {
            return data;
        }

        public void setData(InputStream data)
        {
            this.data = data;
        }

        public Method getRequestMethod()
        {
            return requestMethod;
        }

        public void setRequestMethod(Method requestMethod)
        {
            this.requestMethod = requestMethod;
        }

        public void setChunkedTransfer(boolean chunkedTransfer)
        {
            this.chunkedTransfer = chunkedTransfer;
        }

        public enum Status
        {
            OK(200, "OK"), CREATED(201, "Created"), ACCEPTED(202, "Accepted"), NO_CONTENT(204, "No Content"), PARTIAL_CONTENT(206, "Partial Content"), REDIRECT(301,
            "Moved Permanently"), NOT_MODIFIED(304, "Not Modified"), BAD_REQUEST(400, "Bad Request"), UNAUTHORIZED(401,
            "Unauthorized"), FORBIDDEN(403, "Forbidden"), NOT_FOUND(404, "Not Found"), RANGE_NOT_SATISFIABLE(416,
            "Requested Range Not Satisfiable"), INTERNAL_ERROR(500, "Internal Server Error");
            private final int requestStatus;
            private final String description;

            Status(int requestStatus, String description)
            {
                this.requestStatus = requestStatus;
                this.description = description;
            }

            public int getRequestStatus()
            {
                return this.requestStatus;
            }

            public String getDescription()
            {
                return "" + this.requestStatus + " " + description;
            }
        }
    }

    public static final class ResponseException extends Exception
    {
        private final Response.Status status;

        public ResponseException(Response.Status status, String message)
        {
            super(message);
            this.status = status;
        }

        public ResponseException(Response.Status status, String message, Exception e)
        {
            super(message, e);
            this.status = status;
        }

        public Response.Status getStatus()
        {
            return status;
        }
    }

    private class DefaultTempFileManagerFactory implements TempFileManagerFactory
    {
        @Override
        public TempFileManager create()
        {
            return new DefaultTempFileManager();
        }
    }

    protected class HTTPSession
    {
        public static final int BUFSIZE = 8192;
        private final TempFileManager tempFileManager;
        private final OutputStream outputStream;
        private final Socket socket;
        private InputStream inputStream;
        private int splitbyte;
        private int rlen;
        private String uri;
        private Method method;
        private Map<String, String> parms;
        private Map<String, String> headers;
        private CookieHandler cookies;

        public HTTPSession(TempFileManager tempFileManager, InputStream inputStream, OutputStream outputStream, Socket socket)
        {
            this.tempFileManager = tempFileManager;
            this.inputStream = inputStream;
            this.outputStream = outputStream;
            this.socket = socket;
        }

        public void execute() throws IOException
        {
            try
            {
                byte[] buf = new byte[BUFSIZE];
                splitbyte = 0;
                rlen = 0;
                {
                    int read = inputStream.read(buf, 0, BUFSIZE);
                    if (read == -1)
                    {
                        throw new SocketException("NanoHttpd Shutdown");
                    }
                    while (read > 0)
                    {
                        rlen += read;
                        splitbyte = findHeaderEnd(buf, rlen);
                        if (splitbyte > 0)
                        {
                            break;
                        }
                        read = inputStream.read(buf, rlen, BUFSIZE - rlen);
                    }
                }

                if (splitbyte < rlen)
                {
                    ByteArrayInputStream splitInputStream = new ByteArrayInputStream(buf, splitbyte, rlen - splitbyte);
                    SequenceInputStream sequenceInputStream = new SequenceInputStream(splitInputStream, inputStream);
                    inputStream = sequenceInputStream;
                }

                parms = new HashMap<String, String>();
                headers = new HashMap<String, String>();

                BufferedReader hin = new BufferedReader(new InputStreamReader(new ByteArrayInputStream(buf, 0, rlen)));

                Map<String, String> pre = new HashMap<String, String>();
                decodeHeader(hin, pre, parms, headers);

                method = Method.lookup(pre.get("method"));
                if (method == null)
                {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Syntax error.");
                }

                uri = pre.get("uri");

                cookies = new CookieHandler(headers);

                Response r = serve(this);
                if (r == null)
                {
                    throw new ResponseException(Response.Status.INTERNAL_ERROR, "SERVER INTERNAL ERROR: Serve() returned a null response.");
                }
                else
                {
                    cookies.unloadQueue(r);
                    r.setRequestMethod(method);
                    r.send(outputStream);
                }
            }
            catch (SocketException e)
            {
                throw e;
            }
            catch (IOException ioe)
            {
                Response r = new Response(Response.Status.INTERNAL_ERROR, MIME_PLAINTEXT, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage());
                r.send(outputStream);
                safeClose(outputStream);
            }
            catch (ResponseException re)
            {
                Response r = new Response(re.getStatus(), MIME_PLAINTEXT, re.getMessage());
                r.send(outputStream);
                safeClose(outputStream);
            }
            finally
            {
                tempFileManager.clear();
            }
        }

        protected void parseBody(Map<String, String> files) throws IOException, ResponseException
        {
            RandomAccessFile randomAccessFile = null;
            BufferedReader in = null;
            try
            {

                randomAccessFile = getTmpBucket();

                long size;
                if (headers.containsKey("content-length"))
                {
                    size = Integer.parseInt(headers.get("content-length"));
                }
                else if (splitbyte < rlen)
                {
                    size = rlen - splitbyte;
                }
                else
                {
                    size = 0;
                }

                byte[] buf = new byte[512];
                while (rlen >= 0 && size > 0)
                {
                    rlen = inputStream.read(buf, 0, 512);
                    size -= rlen;
                    if (rlen > 0)
                    {
                        randomAccessFile.write(buf, 0, rlen);
                    }
                }

                ByteBuffer fbuf = randomAccessFile.getChannel().map(FileChannel.MapMode.READ_ONLY, 0, randomAccessFile.length());
                randomAccessFile.seek(0);

                InputStream bin = new FileInputStream(randomAccessFile.getFD());
                in = new BufferedReader(new InputStreamReader(bin));

                if (Method.POST.equals(method))
                {
                    String contentType = "";
                    String contentTypeHeader = headers.get("content-type");

                    StringTokenizer st = null;
                    if (contentTypeHeader != null)
                    {
                        st = new StringTokenizer(contentTypeHeader, ",; ");
                        if (st.hasMoreTokens())
                        {
                            contentType = st.nextToken();
                        }
                    }

                    if ("multipart/form-data".equalsIgnoreCase(contentType))
                    {
                        if (!st.hasMoreTokens())
                        {
                            throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Content type is multipart/form-data but boundary missing. Usage: GET /example/file.html");
                        }

                        String boundaryStartString = "boundary=";
                        int boundaryContentStart = contentTypeHeader.indexOf(boundaryStartString) + boundaryStartString.length();
                        String boundary = contentTypeHeader.substring(boundaryContentStart, contentTypeHeader.length());
                        if (boundary.startsWith("\"") && boundary.endsWith("\""))
                        {
                            boundary = boundary.substring(1, boundary.length() - 1);
                        }

                        decodeMultipartData(boundary, fbuf, in, parms, files);
                    }
                    else
                    {
                        String postLine = "";
                        char pbuf[] = new char[512];
                        int read = in.read(pbuf);
                        while (read >= 0 && !postLine.endsWith("\r\n"))
                        {
                            postLine += String.valueOf(pbuf, 0, read);
                            read = in.read(pbuf);
                        }
                        postLine = postLine.trim();
                        decodeParms(postLine, parms);
                    }
                }
                else if (Method.PUT.equals(method))
                {
                    files.put("content", saveTmpFile(fbuf, 0, fbuf.limit()));
                }
            }
            finally
            {
                safeClose(randomAccessFile);
                safeClose(in);
            }
        }

        private void decodeHeader(BufferedReader in, Map<String, String> pre, Map<String, String> parms, Map<String, String> headers)
                throws ResponseException
        {
            try
            {
                String inLine = in.readLine();
                if (inLine == null)
                {
                    return;
                }

                StringTokenizer st = new StringTokenizer(inLine);
                if (!st.hasMoreTokens())
                {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Syntax error. Usage: GET /example/file.html");
                }

                pre.put("method", st.nextToken());

                if (!st.hasMoreTokens())
                {
                    throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Missing URI. Usage: GET /example/file.html");
                }

                String uri = st.nextToken();

                int qmi = uri.indexOf('?');
                if (qmi >= 0)
                {
                    decodeParms(uri.substring(qmi + 1), parms);
                    uri = decodePercent(uri.substring(0, qmi));
                }
                else
                {
                    uri = decodePercent(uri);
                }

                if (st.hasMoreTokens())
                {
                    String line = in.readLine();
                    while (line != null && line.trim().length() > 0)
                    {
                        int p = line.indexOf(':');
                        if (p >= 0)
                        {
                            headers.put(line.substring(0, p).trim().toLowerCase(), line.substring(p + 1).trim());
                        }
                        line = in.readLine();
                    }
                }

                pre.put("uri", uri);
            }
            catch (IOException ioe)
            {
                throw new ResponseException(Response.Status.INTERNAL_ERROR, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage(), ioe);
            }
        }

        private void decodeMultipartData(String boundary, ByteBuffer fbuf, BufferedReader in, Map<String, String> parms,
                Map<String, String> files) throws ResponseException
        {
            try
            {
                int[] bpositions = getBoundaryPositions(fbuf, boundary.getBytes());
                int boundarycount = 1;
                String mpline = in.readLine();
                while (mpline != null)
                {
                    if (!mpline.contains(boundary))
                    {
                        throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Content type is multipart/form-data but next chunk does not start with boundary. Usage: GET /example/file.html");
                    }
                    boundarycount++;
                    Map<String, String> item = new HashMap<String, String>();
                    mpline = in.readLine();
                    while (mpline != null && mpline.trim().length() > 0)
                    {
                        int p = mpline.indexOf(':');
                        if (p != -1)
                        {
                            item.put(mpline.substring(0, p).trim().toLowerCase(), mpline.substring(p + 1).trim());
                        }
                        mpline = in.readLine();
                    }
                    if (mpline != null)
                    {
                        String contentDisposition = item.get("content-disposition");
                        if (contentDisposition == null)
                        {
                            throw new ResponseException(Response.Status.BAD_REQUEST, "BAD REQUEST: Content type is multipart/form-data but no content-disposition info found. Usage: GET /example/file.html");
                        }
                        StringTokenizer st = new StringTokenizer(contentDisposition, "; ");
                        Map<String, String> disposition = new HashMap<String, String>();
                        while (st.hasMoreTokens())
                        {
                            String token = st.nextToken();
                            int p = token.indexOf('=');
                            if (p != -1)
                            {
                                disposition.put(token.substring(0, p).trim().toLowerCase(), token.substring(p + 1).trim());
                            }
                        }
                        String pname = disposition.get("name");
                        pname = pname.substring(1, pname.length() - 1);

                        String value = "";
                        if (item.get("content-type") == null)
                        {
                            while (mpline != null && !mpline.contains(boundary))
                            {
                                mpline = in.readLine();
                                if (mpline != null)
                                {
                                    int d = mpline.indexOf(boundary);
                                    if (d == -1)
                                    {
                                        value += mpline;
                                    }
                                    else
                                    {
                                        value += mpline.substring(0, d - 2);
                                    }
                                }
                            }
                        }
                        else
                        {
                            if (boundarycount > bpositions.length)
                            {
                                throw new ResponseException(Response.Status.INTERNAL_ERROR, "Error processing request");
                            }
                            int offset = stripMultipartHeaders(fbuf, bpositions[boundarycount - 2]);
                            String path = saveTmpFile(fbuf, offset, bpositions[boundarycount - 1] - offset - 4);
                            files.put(pname, path);
                            value = disposition.get("filename");
                            value = value.substring(1, value.length() - 1);
                            do
                            {
                                mpline = in.readLine();
                            }
                            while (mpline != null && !mpline.contains(boundary));
                        }
                        parms.put(pname, value);
                    }
                }
            }
            catch (IOException ioe)
            {
                throw new ResponseException(Response.Status.INTERNAL_ERROR, "SERVER INTERNAL ERROR: IOException: " + ioe.getMessage(), ioe);
            }
        }

        private int findHeaderEnd(final byte[] buf, int rlen)
        {
            int splitbyte = 0;
            while (splitbyte + 3 < rlen)
            {
                if (buf[splitbyte] == '\r' && buf[splitbyte + 1] == '\n' && buf[splitbyte + 2] == '\r' && buf[splitbyte + 3] == '\n')
                {
                    return splitbyte + 4;
                }
                splitbyte++;
            }
            return 0;
        }

        private int[] getBoundaryPositions(ByteBuffer b, byte[] boundary)
        {
            int matchcount = 0;
            int matchbyte = -1;
            List<Integer> matchbytes = new ArrayList<Integer>();
            for (int i = 0; i < b.limit(); i++)
            {
                if (b.get(i) == boundary[matchcount])
                {
                    if (matchcount == 0)
                    {
                        matchbyte = i;
                    }
                    matchcount++;
                    if (matchcount == boundary.length)
                    {
                        matchbytes.add(matchbyte);
                        matchcount = 0;
                        matchbyte = -1;
                    }
                }
                else
                {
                    i -= matchcount;
                    matchcount = 0;
                    matchbyte = -1;
                }
            }
            int[] ret = new int[matchbytes.size()];
            for (int i = 0; i < ret.length; i++)
            {
                ret[i] = matchbytes.get(i);
            }
            return ret;
        }

        private String saveTmpFile(ByteBuffer b, int offset, int len)
        {
            String path = "";
            if (len > 0)
            {
                FileOutputStream fileOutputStream = null;
                try
                {
                    TempFile tempFile = tempFileManager.createTempFile();
                    ByteBuffer src = b.duplicate();
                    fileOutputStream = new FileOutputStream(tempFile.getName());
                    FileChannel dest = fileOutputStream.getChannel();
                    src.position(offset).limit(offset + len);
                    dest.write(src.slice());
                    path = tempFile.getName();
                }
                catch (Exception e)
                {
                    TFM_Log.severe(e);
                }
                finally
                {
                    safeClose(fileOutputStream);
                }
            }
            return path;
        }

        private RandomAccessFile getTmpBucket()
        {
            try
            {
                TempFile tempFile = tempFileManager.createTempFile();
                return new RandomAccessFile(tempFile.getName(), "rw");
            }
            catch (Exception e)
            {
                TFM_Log.severe(e);
            }
            return null;
        }

        private int stripMultipartHeaders(ByteBuffer b, int offset)
        {
            int i;
            for (i = offset; i < b.limit(); i++)
            {
                if (b.get(i) == '\r' && b.get(++i) == '\n' && b.get(++i) == '\r' && b.get(++i) == '\n')
                {
                    break;
                }
            }
            return i + 1;
        }

        private void decodeParms(String parms, Map<String, String> p)
        {
            if (parms == null)
            {
                p.put(QUERY_STRING_PARAMETER, "");
                return;
            }

            p.put(QUERY_STRING_PARAMETER, parms);
            StringTokenizer st = new StringTokenizer(parms, "&");
            while (st.hasMoreTokens())
            {
                String e = st.nextToken();
                int sep = e.indexOf('=');
                if (sep >= 0)
                {
                    p.put(decodePercent(e.substring(0, sep)).trim(),
                            decodePercent(e.substring(sep + 1)));
                }
                else
                {
                    p.put(decodePercent(e).trim(), "");
                }
            }
        }

        public final Map<String, String> getParms()
        {
            return parms;
        }

        public final Map<String, String> getHeaders()
        {
            return headers;
        }

        public final String getUri()
        {
            return uri;
        }

        public final Method getMethod()
        {
            return method;
        }

        public final InputStream getInputStream()
        {
            return inputStream;
        }

        public CookieHandler getCookies()
        {
            return cookies;
        }

        public Socket getSocket()
        {
            return socket;
        }
    }

    public static class Cookie
    {
        private String n, v, e;

        public Cookie(String name, String value, String expires)
        {
            n = name;
            v = value;
            e = expires;
        }

        public Cookie(String name, String value)
        {
            this(name, value, 30);
        }

        public Cookie(String name, String value, int numDays)
        {
            n = name;
            v = value;
            e = getHTTPTime(numDays);
        }

        public String getHTTPHeader()
        {
            String fmt = "%s=%s; expires=%s";
            return String.format(fmt, n, v, e);
        }

        public static String getHTTPTime(int days)
        {
            Calendar calendar = Calendar.getInstance();
            SimpleDateFormat dateFormat = new SimpleDateFormat("EEE, dd MMM yyyy HH:mm:ss z", Locale.US);
            dateFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
            calendar.add(Calendar.DAY_OF_MONTH, days);
            return dateFormat.format(calendar.getTime());
        }
    }

    public class CookieHandler implements Iterable<String>
    {
        private HashMap<String, String> cookies = new HashMap<String, String>();
        private ArrayList<Cookie> queue = new ArrayList<Cookie>();

        public CookieHandler(Map<String, String> httpHeaders)
        {
            String raw = httpHeaders.get("cookie");
            if (raw != null)
            {
                String[] tokens = raw.split(";");
                for (String token : tokens)
                {
                    String[] data = token.trim().split("=");
                    if (data.length == 2)
                    {
                        cookies.put(data[0], data[1]);
                    }
                }
            }
        }

        @Override
        public Iterator<String> iterator()
        {
            return cookies.keySet().iterator();
        }

        public String read(String name)
        {
            return cookies.get(name);
        }

        public void set(String name, String value, int expires)
        {
            queue.add(new Cookie(name, value, Cookie.getHTTPTime(expires)));
        }

        public void set(Cookie cookie)
        {
            queue.add(cookie);
        }

        public void delete(String name)
        {
            set(name, "-delete-", -30);
        }

        public void unloadQueue(Response response)
        {
            for (Cookie cookie : queue)
            {
                response.addHeader("Set-Cookie", cookie.getHTTPHeader());
            }
        }
    }
}
