using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using CryptRunner.Data;

namespace CryptRunner.ViewModels
{
    public class ItemViewModel
    {
        private int _itemId;

        public int ItemId
        {
            get
            {
                return _itemId;
            }
        }

        //public string DateCreatedHourMinute
        //{
        //    get
        //    {
        //        var formatter = new Windows.Globalization.DateTimeFormatting.DateTimeFormatter("hour minute");
        //        return formatter.Format(DateCreated);
        //    }
        //}

        public string Title { get; set; }
        public Type PageType { get; set; }

        public ItemViewModel()
        {
        }

        public static ItemViewModel FromItem(Item item)
        {
            var viewModel = new ItemViewModel();

            viewModel._itemId = item.Id;
            viewModel.PageType = item.PageType;
            viewModel.Title = item.Title;

            return viewModel;
        }
    }
}