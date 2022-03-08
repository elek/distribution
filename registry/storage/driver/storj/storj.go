// Package s3 provides a storagedriver.StorageDriver implementation to
// store blobs in Amazon S3 cloud storage.
//
// This package leverages the official aws client library for interfacing with
// S3.
//
// Because S3 is a key, value store the Stat call does not support last modification
// time for directories (directories are an abstraction for key, value stores)
//
// Keep in mind that S3 guarantees only read-after-write consistency for new
// objects, but no read-after-update or list-after-write consistency.
package s3

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strings"

	"storj.io/uplink"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/base"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
)

const driverName = "storj"

type DriverParameters struct {
	AccessGrant string
	Bucket      string
}

func init() {
	factory.Register("storj", &storjDriverFactory{})
}

// storjDriverFactory implements the factory.StorageDriverFactory interface
type storjDriverFactory struct{}

func (factory *storjDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	return FromParameters(parameters)
}

type driver struct {
	AccessGrant *uplink.Access
	Project     *uplink.Project
	Bucket      string
}

type baseEmbed struct {
	base.Base
}

// Driver is a storagedriver.StorageDriver implementation backed by Amazon S3
// Objects are stored at absolute keys in the provided bucket.
type Driver struct {
	baseEmbed
}

// FromParameters constructs a new Driver with a given parameters map
// Required parameters:
// - accessgrant
// - bucket
func FromParameters(parameters map[string]interface{}) (*Driver, error) {
	accessGrant := parameters["accessgrant"]
	if os.Getenv("UPLINK_ACCESS") != "" {
		accessGrant = os.Getenv("UPLINK_ACCESS")
	}

	if accessGrant == nil {
		return nil, fmt.Errorf("no accessgrant parameter provided")
	}

	bucket := parameters["bucket"]
	if os.Getenv("UPLINK_BUCKET") != "" {
		bucket = os.Getenv("UPLINK_BUCKET")
	}
	if bucket == nil || fmt.Sprint(bucket) == "" {
		return nil, fmt.Errorf("no bucket parameter provided")
	}

	params := DriverParameters{
		fmt.Sprint(accessGrant),
		fmt.Sprint(bucket),
	}

	return New(params)
}

// getParameterAs
// New constructs a new Driver with the given AWS credentials, region, encryption flag, and
// bucketName
func New(params DriverParameters) (*Driver, error) {
	accessGrant, err := uplink.ParseAccess(params.AccessGrant)
	if err != nil {
		return nil, err
	}

	// TODO close it somehow
	project, err := uplink.OpenProject(context.TODO(), accessGrant)
	if err != nil {
		return nil, err
	}

	d := &driver{
		AccessGrant: accessGrant,
		Project:     project,
		Bucket:      params.Bucket,
	}

	return &Driver{
		baseEmbed: baseEmbed{
			Base: base.Base{
				StorageDriver: d,
			},
		},
	}, nil
}

// Implement the storagedriver.StorageDriver interface
func (d *driver) Name() string {
	return driverName
}

// GetContent retrieves the content stored at "path" as a []byte.
func (d *driver) GetContent(ctx context.Context, path string) (_ []byte, err error) {
	fmt.Println("GetContent", path)
	download, err := d.Project.DownloadObject(ctx, d.Bucket, storjPath(path), nil)
	if err != nil {
		if errors.Is(err, uplink.ErrObjectNotFound) {
			return nil, storagedriver.PathNotFoundError{
				DriverName: driverName,
				Path:       path,
			}
		}
		return nil, err
	}

	defer func() {
		download.Close()
	}()

	data, err := ioutil.ReadAll(download)
	if err != nil {
		if errors.Is(err, uplink.ErrObjectNotFound) {
			return nil, storagedriver.PathNotFoundError{
				DriverName: driverName,
				Path:       path,
			}
		}
		return nil, err
	}
	return data, nil
}

// PutContent stores the []byte content at a location designated by "path".
func (d *driver) PutContent(ctx context.Context, path string, contents []byte) error {
	fmt.Println("PutContent", path)
	upload, err := d.Project.UploadObject(ctx, d.Bucket, storjPath(path), nil)
	if err != nil {
		return err
	}

	_, err = upload.Write(contents)
	if err != nil {
		_ = upload.Abort()
		return err
	}

	err = upload.Commit()
	if err != nil {
		_ = upload.Abort()
		return err
	}

	return nil
}

// Reader retrieves an io.ReadCloser for the content stored at "path" with a
// given byte offset.
func (d *driver) Reader(ctx context.Context, path string, offset int64) (io.ReadCloser, error) {
	fmt.Println("Reader", path)

	download, err := d.Project.DownloadObject(ctx, d.Bucket, storjPath(path), &uplink.DownloadOptions{
		Offset: offset,
		Length: -1,
	})
	if err != nil {
		if errors.Is(err, uplink.ErrObjectNotFound) {
			return nil, storagedriver.PathNotFoundError{
				DriverName: driverName,
				Path:       path,
			}
		}
		return nil, err
	}

	return download, nil
}

func storjPath(path string) string {
	return strings.TrimLeft(path, "/")
}

// Writer returns a FileWriter which will store the content written to it
// at the location designated by "path" after the call to Commit.
func (d *driver) Writer(ctx context.Context, path string, appendParam bool) (storagedriver.FileWriter, error) {
	fmt.Println("Writer", path)

	key := storjPath(path)

	var uploadID string
	partNumber := uint32(0)
	var size int64
	if appendParam {
		uploads := d.Project.ListUploads(ctx, d.Bucket, &uplink.ListUploadsOptions{
			Prefix: key,
		})

		for uploads.Next() {
			item := uploads.Item()
			uploadID = item.UploadID
		}
		if err := uploads.Err(); err != nil {
			return nil, err
		}

		// TODO list all parts
		parts := d.Project.ListUploadParts(ctx, d.Bucket, key, uploadID, nil)
		for parts.Next() {
			item := parts.Item()
			partNumber = item.PartNumber
			size += item.Size
		}
		if err := parts.Err(); err != nil {
			return nil, err
		}

		partNumber++
	} else {
		upload, err := d.Project.BeginUpload(ctx, d.Bucket, key, nil)
		if err != nil {
			return nil, err
		}
		uploadID = upload.UploadID
	}

	uploadPart, err := d.Project.UploadPart(ctx, d.Bucket, key, uploadID, uint32(partNumber))
	if err != nil {
		return nil, err
	}

	return d.newWriter(ctx, d.Project, d.Bucket, key, uploadID, size, uploadPart), nil
}

// Stat retrieves the FileInfo for the given path, including the current size
// in bytes and the creation time.
func (d *driver) Stat(ctx context.Context, path string) (storagedriver.FileInfo, error) {
	fmt.Println("Stat", path)
	if path == "/" {
		return storagedriver.FileInfoInternal{FileInfoFields: storagedriver.FileInfoFields{
			Path:  path,
			IsDir: true,
		}}, nil
	}
	// TODO we need to return stat for dirs
	object, err := d.Project.StatObject(ctx, d.Bucket, storjPath(path))
	if err != nil {
		if errors.Is(err, uplink.ErrObjectNotFound) {
			return nil, storagedriver.PathNotFoundError{
				DriverName: driverName,
				Path:       path,
			}
		}

		return nil, err
	}

	fi := storagedriver.FileInfoFields{
		Path:    "/" + object.Key,
		Size:    object.System.ContentLength,
		ModTime: object.System.Created,
		IsDir:   object.IsPrefix,
	}

	return storagedriver.FileInfoInternal{FileInfoFields: fi}, nil
}

// List returns a list of the objects that are direct descendants of the given path.
func (d *driver) List(ctx context.Context, opath string) ([]string, error) {
	fmt.Println("List", opath)
	path := opath
	if path != "/" && path[len(path)-1] != '/' {
		path = path + "/"
	}

	// This is to cover for the cases when the rootDirectory of the driver is either "" or "/".
	// In those cases, there is no root prefix to replace and we must actually add a "/" to all
	// results in order to keep them as valid paths as recognized by storagedriver.PathRegexp
	// prefix := ""
	// if storjPath("") == "" {
	// 	prefix = "/"
	// }

	iterator := d.Project.ListObjects(ctx, d.Bucket, &uplink.ListObjectsOptions{
		Prefix: storjPath(path),
	})

	found := false
	names := []string{}
	for iterator.Next() {
		item := iterator.Item()

		names = append(names, "/"+strings.TrimRight(item.Key, "/"))
		found = true
	}
	if err := iterator.Err(); err != nil {
		return nil, err
	}
	if !found && opath != "/" {
		return nil, storagedriver.PathNotFoundError{
			DriverName: driverName,
			Path:       opath,
		}
	}

	return names, nil
}

// Move moves an object stored at sourcePath to destPath, removing the original
// object.
func (d *driver) Move(ctx context.Context, sourcePath string, destPath string) error {
	// TODO maybe we should stat first and if exists delete second
	for {
		err := d.Project.MoveObject(ctx, d.Bucket, storjPath(sourcePath), d.Bucket, storjPath(destPath), nil)
		if err != nil {
			if errors.Is(err, uplink.ErrObjectNotFound) {
				return storagedriver.PathNotFoundError{
					DriverName: driverName,
					Path:       sourcePath,
				}
			} else if strings.Contains(err.Error(), "object already exists") { // TODO have this error in uplink
				_, err := d.Project.DeleteObject(ctx, d.Bucket, storjPath(destPath))
				if err != nil {
					return err
				}
				continue
			}
			return err
		}
		return nil
	}
}

// Delete recursively deletes all objects stored at "path" and its subpaths.
// We must be careful since S3 does not guarantee read after delete consistency
func (d *driver) Delete(ctx context.Context, path string) error {
	fmt.Println("Delete", path)
	iterator := d.Project.ListObjects(ctx, d.Bucket, &uplink.ListObjectsOptions{
		Prefix:    storjPath(path) + "/",
		Recursive: true,
	})

	found := false
	for iterator.Next() {
		found = true
		item := iterator.Item()
		_, err := d.Project.DeleteObject(ctx, d.Bucket, item.Key)
		if err != nil {
			return err
		}
	}
	if err := iterator.Err(); err != nil {
		return err
	}

	if found {
		return nil
	}

	object, err := d.Project.DeleteObject(ctx, d.Bucket, storjPath(path))
	if err != nil {
		return err
	}

	if object == nil {
		return storagedriver.PathNotFoundError{
			DriverName: driverName,
			Path:       path,
		}
	}
	return nil
}

// URLFor returns a URL which may be used to retrieve the content stored at the given path.
// May return an UnsupportedMethodErr in certain StorageDriver implementations.
func (d *driver) URLFor(ctx context.Context, path string, options map[string]interface{}) (string, error) {
	// TODO most probably we can make linksharing link
	return "", storagedriver.ErrUnsupportedMethod{}
}

// Walk traverses a filesystem defined within driver, starting
// from the given path, calling f on each file
func (d *driver) Walk(ctx context.Context, from string, f storagedriver.WalkFn) error {
	fmt.Println("Walk", from)
	return nil
}

type writer struct {
	ctx     context.Context
	driver  *driver
	project *uplink.Project

	bucket   string
	key      string
	uploadID string
	upload   *uplink.PartUpload
	size     int64
	partSize int64

	closed    bool
	committed bool
	cancelled bool
}

func (d *driver) newWriter(ctx context.Context, project *uplink.Project, bucket, key string, uploadID string, size int64, upload *uplink.PartUpload) storagedriver.FileWriter {
	return &writer{
		ctx:      ctx,
		driver:   d,
		project:  project,
		bucket:   bucket,
		key:      key,
		upload:   upload,
		uploadID: uploadID,
		size:     size,
	}
}

func (w *writer) Write(p []byte) (int, error) {
	if w.closed {
		return 0, fmt.Errorf("already closed")
	} else if w.committed {
		return 0, fmt.Errorf("already committed")
	} else if w.cancelled {
		return 0, fmt.Errorf("already cancelled")
	}

	n, err := w.upload.Write(p)
	w.size += int64(n)
	w.partSize += int64(n)
	if err != nil {
		return n, err
	}
	return n, nil
}

func (w *writer) Size() int64 {
	return w.size
}

func (w *writer) Cancel() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	}
	w.cancelled = true

	// TODO combine errors from Abort with AbortUpload
	_ = w.upload.Abort()

	return w.project.AbortUpload(w.ctx, w.bucket, w.key, w.uploadID)
}

func (w *writer) Commit() error {
	if w.closed {
		return fmt.Errorf("already closed")
	} else if w.committed {
		return fmt.Errorf("already committed")
	} else if w.cancelled {
		return fmt.Errorf("already cancelled")
	}
	w.committed = true

	err := w.CommitPart()
	if err != nil {
		return err
	}

	_, err = w.project.CommitUpload(w.ctx, w.bucket, w.key, w.uploadID, nil)
	return err
}

func (w *writer) Close() error {
	if w.closed {
		return fmt.Errorf("already closed")
	}
	w.closed = true

	return w.CommitPart()
}

func (w *writer) CommitPart() error {
	if w.partSize > 0 {
		err := w.upload.Commit()
		if err != nil && !errors.Is(err, uplink.ErrUploadDone) {
			return err
		}
	}
	return nil
}
