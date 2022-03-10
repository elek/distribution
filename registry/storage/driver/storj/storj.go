// Package storj provides a storagedriver.StorageDriver implementation to
// store blobs in Storj DCS decentralized storage.
package storj

import (
	"context"
	"errors"
	"fmt"
	"github.com/distribution/distribution/v3/registry/auth/storj"
	"io"
	"io/ioutil"
	"strings"

	"storj.io/uplink"

	storagedriver "github.com/distribution/distribution/v3/registry/storage/driver"
	"github.com/distribution/distribution/v3/registry/storage/driver/base"
	"github.com/distribution/distribution/v3/registry/storage/driver/factory"
	"github.com/zeebo/errs"
)

const driverName = "storj"

//DriverParameters A struct that encapsulates all of the driver parameters after all values have been set.
type DriverParameters struct {
	AccessGrant string
	Bucket      string
}

func init() {
	factory.Register("storj", &storjDriverFactory{})
}

// storjDriverFactory implements the factory.StorageDriverFactory interface.
type storjDriverFactory struct{}

func (factory *storjDriverFactory) Create(parameters map[string]interface{}) (storagedriver.StorageDriver, error) {
	return New()
}

type driver struct {
}

type baseEmbed struct {
	base.Base
}

// Driver is a storagedriver.StorageDriver implementation backed by Storj DCS.
// Objects are stored at absolute keys in the provided bucket.
type Driver struct {
	baseEmbed
}

// New constructs a new Driver with the given Access Grant and bucketName.
func New() (*Driver, error) {

	d := &driver{}

	return &Driver{
		baseEmbed: baseEmbed{
			Base: base.Base{
				StorageDriver: d,
			},
		},
	}, nil
}

func storjKey(path string) string {
	return strings.TrimLeft(path, "/")
}

// Implement the storagedriver.StorageDriver interface
func (d *driver) Name() string {
	return driverName
}

func (d *driver) openProjectWithBucket(ctx context.Context) (*uplink.Project, string, error) {
	access := storj.GetGrant(ctx)
	accessGrant, err := uplink.ParseAccess(access)
	if err != nil {
		return nil, "", err
	}

	project, err := uplink.OpenProject(ctx, accessGrant)
	if err != nil {
		return nil, "", err
	}
	return project, "registry2", err

}

// GetContent retrieves the content stored at "path" as a []byte.
func (d *driver) GetContent(ctx context.Context, path string) (_ []byte, err error) {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return nil, err
	}
	defer project.Close()

	download, err := project.DownloadObject(ctx, bucket, storjKey(path), nil)
	if err != nil {
		return nil, convertError(path, err)
	}

	defer func() {
		err = errs.Combine(err, download.Close())
	}()

	data, err := ioutil.ReadAll(download)
	if err != nil {
		return nil, convertError(path, err)
	}
	return data, nil
}

// PutContent stores the []byte content at a location designated by "path".
func (d *driver) PutContent(ctx context.Context, path string, contents []byte) error {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return err
	}
	defer project.Close()

	upload, err := project.UploadObject(ctx, bucket, storjKey(path), nil)
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
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return nil, err
	}
	defer project.Close()

	download, err := project.DownloadObject(ctx, bucket, storjKey(path), &uplink.DownloadOptions{
		Offset: offset,
		Length: -1,
	})
	if err != nil {
		return nil, convertError(path, err)
	}

	return download, nil
}

// Writer returns a FileWriter which will store the content written to it
// at the location designated by "path" after the call to Commit.
func (d *driver) Writer(ctx context.Context, path string, appendParam bool) (storagedriver.FileWriter, error) {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return nil, err
	}
	defer project.Close()

	key := storjKey(path)

	// TODO verify that parts are not too small

	var uploadID string
	partNumber := uint32(1)
	var size int64
	if !appendParam {
		upload, err := project.BeginUpload(ctx, bucket, key, nil)
		if err != nil {
			return nil, err
		}
		uploadID = upload.UploadID
	} else {
		uploads := project.ListUploads(ctx, bucket, &uplink.ListUploadsOptions{
			Prefix: key,
		})

		// currently we should get only single upload
		for uploads.Next() {
			item := uploads.Item()
			uploadID = item.UploadID

			continue
		}
		if err := uploads.Err(); err != nil {
			return nil, err
		}

		parts := project.ListUploadParts(ctx, bucket, key, uploadID, nil)
		for parts.Next() {
			item := parts.Item()
			partNumber = item.PartNumber
			size += item.Size
		}
		if err := parts.Err(); err != nil {
			return nil, err
		}

		partNumber++
	}

	uploadPart, err := project.UploadPart(ctx, bucket, key, uploadID, uint32(partNumber))
	if err != nil {
		return nil, convertError(path, err)
	}

	return d.newWriter(ctx, project, bucket, key, uploadID, size, uploadPart), nil
}

// Stat retrieves the FileInfo for the given path, including the current size
// in bytes and the creation time.
func (d *driver) Stat(ctx context.Context, path string) (storagedriver.FileInfo, error) {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return nil, err
	}

	defer project.Close()

	if path == "/" {
		return storagedriver.FileInfoInternal{FileInfoFields: storagedriver.FileInfoFields{
			Path:  path,
			IsDir: true,
		}}, nil
	}

	// TODO we should be able to stat dir or object with single list object
	// we need to parse from path to get one level less dir and use cursor
	// for listing. Cursor should be calculated as key before last path entry.

	iterator := project.ListObjects(ctx, bucket, &uplink.ListObjectsOptions{
		Prefix: storjKey(path) + "/",
	})

	// it prefix has at least one entry its a dir
	found := iterator.Next()
	if err := iterator.Err(); err != nil {
		return nil, err
	}

	if found {
		return storagedriver.FileInfoInternal{FileInfoFields: storagedriver.FileInfoFields{
			Path:  path,
			IsDir: true,
		}}, nil
	}

	object, err := project.StatObject(ctx, bucket, storjKey(path))
	if err != nil {
		return nil, convertError(path, err)
	}

	fi := storagedriver.FileInfoFields{
		Path:    path,
		Size:    object.System.ContentLength,
		ModTime: object.System.Created,
		IsDir:   object.IsPrefix,
	}

	return storagedriver.FileInfoInternal{FileInfoFields: fi}, nil
}

// List returns a list of the objects that are direct descendants of the given path.
func (d *driver) List(ctx context.Context, opath string) ([]string, error) {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return nil, err
	}
	defer project.Close()

	prefix := opath
	if prefix != "/" && prefix[len(prefix)-1] != '/' {
		prefix = prefix + "/"
	}

	// This is to cover for the cases when the rootDirectory of the driver is either "" or "/".
	// In those cases, there is no root prefix to replace and we must actually add a "/" to all
	// results in order to keep them as valid paths as recognized by storagedriver.PathRegexp
	// prefix := ""
	// if storjKey("") == "" {
	// 	prefix = "/"
	// }

	iterator := project.ListObjects(ctx, bucket, &uplink.ListObjectsOptions{
		Prefix: storjKey(prefix),
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
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return err
	}
	defer project.Close()

	// TODO maybe we should stat first and if exists delete second
	for {
		err := project.MoveObject(ctx, bucket, storjKey(sourcePath), bucket, storjKey(destPath), nil)
		if err != nil {
			if errors.Is(err, uplink.ErrObjectNotFound) {
				return storagedriver.PathNotFoundError{
					DriverName: driverName,
					Path:       sourcePath,
				}
			} else if strings.Contains(err.Error(), "object already exists") { // TODO have this error in uplink
				_, err := project.DeleteObject(ctx, bucket, storjKey(destPath))
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
func (d *driver) Delete(ctx context.Context, path string) error {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return err
	}
	defer project.Close()

	iterator := project.ListObjects(ctx, bucket, &uplink.ListObjectsOptions{
		Prefix:    storjKey(path) + "/",
		Recursive: true,
	})

	found := false
	for iterator.Next() {
		found = true
		item := iterator.Item()
		_, err := project.DeleteObject(ctx, bucket, item.Key)
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

	object, err := project.DeleteObject(ctx, bucket, storjKey(path))
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
	prefix := storjKey(from)

	if prefix != "" {
		prefix += "/"
	}

	return d.doWalk(ctx, prefix, f)
}

func (d *driver) doWalk(ctx context.Context, prefix string, f storagedriver.WalkFn) error {
	project, bucket, err := d.openProjectWithBucket(ctx)
	if err != nil {
		return err
	}
	defer project.Close()

	storjPrefix := storjKey(prefix)

	// TODO could we do this with single recursive request?
	objects := project.ListObjects(ctx, bucket, &uplink.ListObjectsOptions{
		Prefix: storjPrefix,
	})

	for objects.Next() {
		item := objects.Item()

		path := "/" + item.Key
		path = strings.TrimRight(path, "/")

		fileInfo := storagedriver.FileInfoInternal{FileInfoFields: storagedriver.FileInfoFields{
			Path:    path,
			Size:    item.System.ContentLength,
			ModTime: item.System.Created,
			IsDir:   item.IsPrefix,
		}}
		err := f(fileInfo)
		if err != nil {
			if err == storagedriver.ErrSkipDir {
				continue
			}
			return err
		}

		if item.IsPrefix {
			err = d.doWalk(ctx, item.Key, f)
			if err != nil {
				return err
			}
		}
	}
	if err := objects.Err(); err != nil {
		return err
	}

	return nil
}

// TODO should we buffer data written to 'writer'?

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

// Size returns the number of bytes written to this FileWriter.
func (w *writer) Size() int64 {
	return w.size
}

// Cancel removes any written content from this FileWriter.
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

// Commit flushes all content written to this FileWriter and makes it
// available for future calls to StorageDriver.GetContent and
// StorageDriver.Reader.
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
	if w.partSize <= 0 {
		return nil
	}

	err := w.upload.Commit()
	if err != nil && !errors.Is(err, uplink.ErrUploadDone) {
		return err
	}
	return nil
}

func convertError(path string, err error) error {
	if errors.Is(err, uplink.ErrObjectNotFound) {
		return storagedriver.PathNotFoundError{
			DriverName: driverName,
			Path:       path,
		}
	}
	return err
}
