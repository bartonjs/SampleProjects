using System.Collections.Generic;

namespace CryptRunner.Data
{
    public class ItemsDataSource
    {
        private static List<Item> _items = new List<Item>()
        {
            new Item()
            {
                Id = 0,
                PageType = typeof(HashingPage),
                Title = "Hashing",
            },
            new Item()
            {
                Id = 1,
                PageType = typeof(HmacPage),
                Title = "HMAC",
            },
            new Item()
            {
                Id = 2,
                PageType = typeof(RSAPPage),
                Title = "RSA",
            },
            new Item()
            {
                Id = 3,
                PageType = typeof(DoEverythingPage),
                Title = "Misc",
            },
        };

        public static IList<Item> GetAllItems()
        {
            return _items;
        }

        public static Item GetItemById(int id)
        {
            return _items[id];
        }
    }
}