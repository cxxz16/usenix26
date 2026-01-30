<?php

class AssetController extends ElementControllerBase implements KernelControllerEventInterface
{

public function downloadAsZipAddFilesAction(Request $request)
    {
        $zipFile = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/download-zip-' . $request->get('jobId') . '.zip';
        $asset = Asset::getById((int) $request->get('id'));
        $success = false;

        if (!$asset) {
            throw $this->createNotFoundException('Asset not found');
        }

        if ($asset->isAllowed('view')) {
            $zip = new \ZipArchive();
            if (!is_file($zipFile)) {
                $zipState = $zip->open($zipFile, \ZipArchive::CREATE);
            } else {
                $zipState = $zip->open($zipFile);
            }

            if ($zipState === true) {
                $parentPath = $asset->getRealFullPath();
                if ($asset->getId() == 1) {
                    $parentPath = '';
                }

                $db = \Pimcore\Db::get();
                $conditionFilters = [];
                $selectedIds = $request->get('selectedIds', []);

                if (!empty($selectedIds)) {
                    $selectedIds = explode(',', $selectedIds);

                    $quotedSelectedIds = [];
                    foreach ($selectedIds as $selectedId) {
                        if ($selectedId) {
                            $quotedSelectedIds[] = $db->quote($selectedId);
                        }
                    }

                    //add a condition if id numbers are specified
                    $conditionFilters[] = 'id IN (' . implode(',', $quotedSelectedIds) . ')';
                }
                $conditionFilters[] = "type != 'folder' AND path LIKE " . $db->quote(Helper::escapeLike($parentPath) . '/%');
                if (!$this->getAdminUser()->isAdmin()) {
                    $userIds = $this->getAdminUser()->getRoles();
                    $userIds[] = $this->getAdminUser()->getId();
                    $conditionFilters[] = ' ( (select list from users_workspaces_asset where userId in (' . implode(',', $userIds) . ') and LOCATE(CONCAT(path, filename),cpath)=1  ORDER BY LENGTH(cpath) DESC LIMIT 1)=1 OR (select list from users_workspaces_asset where userId in (' . implode(',', $userIds) . ') and LOCATE(cpath,CONCAT(path, filename))=1  ORDER BY LENGTH(cpath) DESC LIMIT 1)=1 )';
                }

                $condition = implode(' AND ', $conditionFilters);

                $assetList = new Asset\Listing();
                $assetList->setCondition($condition);
                $assetList->setOrderKey('LENGTH(path) ASC, id ASC', false);
                $assetList->setOffset((int)$request->get('offset'));
                $assetList->setLimit((int)$request->get('limit'));

                foreach ($assetList as $a) {
                    if ($a->isAllowed('view')) {
                        if (!$a instanceof Asset\Folder) {
                            // add the file with the relative path to the parent directory
                            $zip->addFile($a->getLocalFile(), preg_replace('@^' . preg_quote($asset->getRealPath(), '@') . '@i', '', $a->getRealFullPath()));
                        }
                    }
                }

                $zip->close();
                $success = true;
            }
        }

        return $this->adminJson([ 'success' => $success, ]);
    }

}

?>