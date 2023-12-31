#include "StringsTableModel.h"

#define MAX_PER_PAGE 10000

StringsTableModel::StringsTableModel(PeHandler *peHndl, ColorSettings &_addrColors, QObject *parent)
	: QAbstractTableModel(parent), m_PE(peHndl), 
	stringsMap(nullptr), addrColors(_addrColors),
	pageNum(0),
	limitPerPage(MAX_PER_PAGE)
{
}

QVariant StringsTableModel::headerData(int section, Qt::Orientation orientation, int role) const
{
	if (role != Qt::DisplayRole) return QVariant();
	if (orientation == Qt::Horizontal) {
		switch (section) {
			case COL_OFFSET: return tr("Offset");
			case COL_TYPE: return tr("Type");
			case COL_LENGTH: return tr("Length");
			case COL_STRING : return tr("String");
		}
	}
	return QVariant();
}

Qt::ItemFlags StringsTableModel::flags(const QModelIndex &index) const
{	
	if (!index.isValid()) return Qt::NoItemFlags;
	const Qt::ItemFlags fl = Qt::ItemIsEnabled | Qt::ItemIsSelectable;
	return fl;
}

QVariant StringsTableModel::data(const QModelIndex &index, int role) const
{
	if (!this->stringsMap) {
		return QVariant();
	}
	int column = index.column();
	int row = index.row() + getPageStartIndx();
	if ((size_t)row >= stringsOffsets.size()) return QVariant();

	if (role == Qt::UserRole && column == COL_OFFSET) {
		return qint64(stringsOffsets[row]);
	}
	if (role == Qt::ForegroundRole && column == COL_OFFSET) {
		return this->addrColors.rawColor();
	}
	if (role == Qt::ToolTipRole) {
		switch (column) {
			case COL_OFFSET:
				return "Right click to follow [" + util::translateAddrTypeName(Executable::RAW) + "]";
			case COL_TYPE:
			{
				offset_t strOffset = stringsOffsets[row];
				return stringsMap->isWide(strOffset) ? "Wide" : "Ansi";
			}
			case COL_STRING : 
			{
				offset_t strOffset = stringsOffsets[row];
				QString str = stringsMap->getString(strOffset).trimmed();
				const size_t maxLen = 1000;
				if (str.length() > maxLen) {
					return str.left(maxLen) + "\n[...]";
				}
				return str;
			}
		}
	}
	if (role != Qt::DisplayRole && role != Qt::EditRole) {
		return QVariant();
	}
	offset_t strOffset = stringsOffsets[row];
	switch (column) {
		case COL_OFFSET:
			return QString::number(strOffset, 16);
		case COL_TYPE:
			return stringsMap->isWide(strOffset) ? "W" : "A";
		case COL_LENGTH:
			return stringsMap->getString(strOffset).length();
		case COL_STRING : 
			return stringsMap->getString(strOffset);
	}
	return QVariant();
}

//----

void StringsBrowseWindow::onFilterChanged(QString str)
{

	if (!this->stringsProxyModel) return;
	QRegExp regExp(str.toLower(), Qt::CaseSensitive, QRegExp::FixedString);
	stringsProxyModel->setFilterRegExp(regExp);
}

void StringsBrowseWindow::offsetClicked(offset_t offset, Executable::addr_type type)
{
	if (!this->myPeHndl) {
		return;
	}
	size_t strSize = this->myPeHndl->stringsMap.getStringSize(offset);
	myPeHndl->setDisplayed(false, offset, strSize);
	myPeHndl->setHilighted(offset, strSize);
}

void StringsBrowseWindow::onSave()
{
	QString defaultFileName = this->myPeHndl->getFullName() + ".strings.txt";
	QString filter = tr("Text Files") + "(*.txt);;" + tr("All Files") + "(*)";
	QString fName = QFileDialog::getSaveFileName(this, tr("Save strings as..."), defaultFileName, filter);
	
	if (fName.length() > 0) {
		if (this->myPeHndl->stringsMap.saveToFile(fName)) {
			QMessageBox::information(this, tr("Strings save"), tr("Saved strings to: ") + fName, QMessageBox::Ok);
		}
	}
}

void StringsBrowseWindow::initLayout()
{
	QWidget *widget = new QWidget(this);
	widget->setLayout(&topLayout);
	setCentralWidget(widget);
	saveButton.setText(tr("Save"));

	propertyLayout0.addWidget(&saveButton);

	propertyLayout0.addWidget(new QLabel(tr("Page"), this));
	propertyLayout0.addWidget(&pageSelectBox);

	filterLabel.setText(tr("Search string"));
	propertyLayout0.addWidget(&filterLabel);
	propertyLayout0.addWidget(&filterEdit);
	topLayout.addLayout(&propertyLayout0);
	topLayout.addWidget(&stringsTable);

	connect(&saveButton, SIGNAL(clicked()), this, SLOT(onSave()) );
	connect(&filterEdit, SIGNAL(textChanged(QString)), this, SLOT(onFilterChanged(QString)) );
}
